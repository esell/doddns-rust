extern crate clap;
extern crate futures;
extern crate hyper;
extern crate hyper_tls;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;
extern crate tokio_core;

use std::str;
use std::error::Error;
use clap::{App, Arg};
use std::io;
use futures::{Future, Stream};
use hyper::{Chunk, Client, Method, Request, Uri};
use hyper::header::{Authorization, Bearer, ContentLength, ContentType};
use hyper_tls::HttpsConnector;
use tokio_core::reactor::Core;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct IPRecord {
    ip: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DomainRecord {
    id: u32,
    #[serde(rename = "type")] record_type: String,
    name: String,
    data: String,
    priority: Option<u32>,
    port: Option<u32>,
    weight: Option<u32>,
}

// TODO: add other attributes
#[derive(Serialize, Deserialize, Debug, Clone)]
struct DomainRecords {
    domain_records: Vec<DomainRecord>,
    #[serde(skip)] links: String,
    #[serde(skip)] meta: String,
}

fn main() {
    let matches = App::new("doddns")
        .version("1.0")
        .about("Dynamically update your Digital Ocean DNS entry")
        .arg(
            Arg::with_name("api_key")
                .help("API Key")
                .takes_value(true)
                .short("k")
                .long("apikey")
                .required(true),
        )
        .arg(
            Arg::with_name("domain_name")
                .help("Domain name ex: blah.com")
                .takes_value(true)
                .short("d")
                .long("domain")
                .required(true),
        )
        .arg(
            Arg::with_name("subdomain")
                .help("Subdomain to update")
                .takes_value(true)
                .short("s")
                .long("subdomain")
                .required(true),
        )
        .get_matches();
    let api_key = matches.value_of("api_key").unwrap();
    let domain_name = matches.value_of("domain_name").unwrap();
    let subdomain = matches.value_of("subdomain").unwrap();

    // Get current IP
    let current_ip = match http_req(
        Method::Get,
        String::from("https://api.ipify.org?format=json"),
        false,
        String::from(api_key),
        String::default(),
    ) {
        Ok(s) => {
            let v: IPRecord = serde_json::from_slice(&s)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                .unwrap();
            v.ip
        }
        Err(e) => panic!("Unable to get current IP: {:?}", e),
    };
    println!("current IP address is {}", current_ip);

    // Get current Domain Records
    let domain_records = match http_req(
        Method::Get,
        format!(
            "https://api.digitalocean.com/v2/domains/{}/records",
            domain_name
        ),
        true,
        String::from(api_key),
        String::default(),
    ) {
        Ok(s) => {
            let v: DomainRecords = serde_json::from_slice(&s)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                .unwrap();
            v.domain_records
        }
        Err(e) => panic!("Unable to get domain records: {:?}", e),
    };

    if sub_exists(&domain_records, subdomain.to_string()) {
        println!("subdomain exists, updating...");
        let sub_id = get_sub_id(&domain_records, subdomain.to_string());
        let json_data = json!({"data": &*current_ip});
        // update subdomain
        match http_req(
            Method::Put,
            format!(
                "https://api.digitalocean.com/v2/domains/{}/records/{}",
                domain_name, &*sub_id
            ),
            true,
            String::from(api_key),
            json_data.to_string(),
        ) {
            Ok(s) => {
                println!("update success {}", str::from_utf8(&s).unwrap());
            }
            Err(e) => panic!("Unable to update subdomain: {:?}", e),
        };
    } else {
        println!("subdomain does NOT exist, creating...");
        let json_data = json!({
            "type": "A",
            "name": subdomain,
            "data": &*current_ip,
            "priority": null,
            "port": null,
            "weight": null,
            "ttl": 300,
            "tag": null
        });
        // create subdomain
        match http_req(
            Method::Post,
            format!(
                "https://api.digitalocean.com/v2/domains/{}/records",
                domain_name
            ),
            true,
            String::from(api_key),
            json_data.to_string(),
        ) {
            Ok(s) => {
                println!("create success {}", str::from_utf8(&s).unwrap());
            }
            Err(e) => panic!("Unable to create subdomain: {:?}", e),
        };
    }
}

fn http_req(
    verb: Method,
    uri: String,
    auth: bool,
    api_key: String,
    req_data: String,
) -> Result<Chunk, Box<Error>> {
    let mut core = Core::new()?;
    let handle = core.handle();
    let client = Client::configure()
        .connector(HttpsConnector::new(4, &handle)?)
        .build(&handle);
    let url: Uri = uri.parse()?;
    let mut req = Request::new(verb, url);
    if auth {
        req.headers_mut().set(ContentType::json());
        req.headers_mut().set(Authorization(Bearer {
            token: api_key.to_owned(),
        }));
    }
    if !req_data.is_empty() {
        req.headers_mut().set(ContentLength(req_data.len() as u64));
        req.set_body(req_data);
    }
    let future_req = client.request(req).and_then(|res| res.body().concat2());
    let req_response = core.run(future_req).unwrap();
    Ok(req_response)
}

fn sub_exists(records: &Vec<DomainRecord>, subdomain: String) -> bool {
    for element in records.iter() {
        if element.name == subdomain {
            return true;
        }
    }
    false
}

fn get_sub_id(records: &Vec<DomainRecord>, subdomain: String) -> String {
    for element in records.iter() {
        if element.name == subdomain {
            return element.id.to_string();
        }
    }
    return String::default();
}
