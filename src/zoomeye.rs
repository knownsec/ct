use std::fs;
use std::io::Write;

use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header;
use serde::{Deserialize, Serialize};

pub struct ZoomEye;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Portinfo {
    pub port: u32,
    pub service: String,
    pub app: String,
    pub banner: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct IPInfo {
    pub ip: String,
    pub honeypot: u8,
    pub timestamp: String,
    pub portinfo: Portinfo,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct IPHostInfo {
    pub total: u32,
    pub available: u32,
    pub matches: Vec<IPInfo>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Domain {
    pub name: String,
    pub timestamp: String,
    pub ip: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DomainResult {
    pub status: u32,
    pub total: u32,
    pub r#type: u8,
    pub msg: String,
    pub list: Vec<Domain>,

}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DomainQuery {
    pub query_str: String,
    pub data: DomainResult,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct IPHostInfoQuery {
    pub query_str: String,
    pub data: IPHostInfo,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Resource {
    pub search: u32,
    pub stats: u32,
    pub interval: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct UserInfo {
    pub name: String,
    pub role: String,
    pub expired_at: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct QuotaInfo {
    pub remain_free_quota: u32,
    pub remain_pay_quota: u32,
    pub remain_total_quota: u32,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ResourcesInfoResult {
    pub user_info: UserInfo,
    pub quota_info: QuotaInfo,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ResourcesInfoQuery {
    pub query_str: String,
    pub data: ResourcesInfoResult,
}

impl IPHostInfoQuery {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn query(&mut self) {
        let mut headers = header::HeaderMap::new();
        let apikey = get_apikey().trim().parse().unwrap();
        headers.insert("API-KEY", apikey);
        let client = Client::builder().default_headers(headers).build().unwrap();
        let res = client.get(&self.query_str).send()
            .expect("The access request was unexpected, please check the network.");
        self.data = serde_json::from_str(&res.text().unwrap())
            .expect("The output result is unexpected, please check the permissions.");
    }
}

impl DomainQuery {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn query(&mut self) {
        let mut headers = header::HeaderMap::new();
        let apikey = get_apikey().trim().parse().unwrap();
        headers.insert("API-KEY", apikey);
        let client = Client::builder().default_headers(headers).build().unwrap();
        let res = client.get(&self.query_str).send()
            .expect("The access request was unexpected, please check the network.");
        if res.status() == 200 {
            self.data = serde_json::from_str(&res.text().unwrap())
                .expect("The output result is unexpected, please check the permissions.");
        } else {
            println!("Query url {} error , error code {}", self.query_str, res.status());
        }
    }
}


impl ResourcesInfoQuery {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn query(&mut self) {
        let mut headers = header::HeaderMap::new();
        let apikey = get_apikey().trim().parse().unwrap();
        headers.insert("API-KEY", apikey);
        let client = Client::builder().default_headers(headers).build().unwrap();
        let res = client.get(&self.query_str).send()
            .expect("The access request was unexpected, please check the network.");
        if res.status() == 200 {
            self.data = serde_json::from_str(&res.text().unwrap())
                .expect("The output result is unexpected, please check the permissions.");
        } else {
            println!("Query url {} error , error code {}", self.query_str, res.status());
        }
    }
}




fn get_apikey_file() -> String {
    let os_type = std::env::consts::OS;
    let apikey_dir = format!("{}/.config/zoomeye/setting", dirs::home_dir().unwrap().display());
    fs::create_dir_all(apikey_dir.clone()).unwrap();
    let mut file_path = format!("{}/apikey", apikey_dir.clone());
    if os_type.eq("windows") {
        file_path = file_path.replace("/", "\\");
    }
    file_path
}

fn check_apikey(apikey: &String) -> bool {
    let re = Regex::new(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{5}-[0-9a-fA-F]{4}-[0-9a-fA-F]{11}").unwrap();
    re.is_match(apikey)
}

fn get_apikey() -> String {
    let apikey = fs::read_to_string(get_apikey_file()).expect("\nPlease use command:\nct --init APIKEY.\n");
    apikey
}

impl ZoomEye {
    pub fn init(apikey: String) {
        if check_apikey(&apikey) {
            let mut file = std::fs::File::create(get_apikey_file()).expect("create api key file failed");
            file.write_all(apikey.as_bytes()).expect("write apikey failed");
        }
    }

    pub fn get_base_info() -> ResourcesInfoQuery {
        let mut resource = ResourcesInfoQuery::new();
        resource.query_str = "https://api.zoomeye.org/resources-info".to_string();
        resource.query();
        resource
    }
}
