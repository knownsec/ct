use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Sender};
use std::time::Duration;
use std::time::Instant;

use dnsclient::sync::DNSClient;
use dnsclient::UpstreamServer;
use itertools::Itertools;
use threadpool::ThreadPool;

type SortedDNSList = Vec<(String, u32)>;
pub const DEFAULT_DNS_SERVERS: [&'static str; 13] = [
    "119.29.29.29", "223.5.5.5", "223.6.6.6", "180.76.76.76",
    "114.114.114.114", "114.114.115.115", "1.1.1.1", "8.8.8.8",
    "1.0.0.1", "208.67.222.222", "208.67.220.220", "208.67.222.220",
    "208.67.220.222"];

pub fn get_fast_dns_list(dns_vec: &HashSet<String>, thread_num: usize) -> SortedDNSList {
    let result = Arc::new(Mutex::new(vec![]));
    let tps = ThreadPool::new(thread_num);
    dns_vec.into_iter().for_each(|s| {
        let res = result.clone();
        let tmp_s = format!("{}:53", s);
        tp.execute(move || {
            let mut mres = res.lock().unwrap();
            let avg = get_dns_avg_time(tmp_s.as_str(), 10);
            mres.push((tmp_s.to_string(), avg));
        })
    });
    tps.join();
    let mut data = result.lock().unwrap().clone();
    data.sort_by_key(|e| e.1);
    data
}



pub fn get_dns_avg_time(dns_server: &str, count: u32) -> u32 {
    let dns_servers = vec![UpstreamServer::new(
        SocketAddr::from_str(dns_server).unwrap(),
    )];
    let mut dns_client = DNSClient::new(dns_servers);
    dns_client.set_timeout(Duration::from_millis(100));
    let mut sum = 0;
    for _ in 0..count {
        let start = Instant::now();
        if let Ok(result) = dns_client.query_a("www.baidu.com") {
            if !result.is_empty() {
                sum += start.elapsed().as_millis() as u32;
            }
        }
    }
    sum / count
}


fn run_start(pool: &ThreadPool, dns_client: DNSClient, domain_name: String, tx: Sender<(String, Vec<String>)>) {
    pool.execute(move || {
        if let Ok(result) = dns_client.query_a(domain_name.as_str()) {
            if !result.is_empty() {
                tx.send((domain_name, result.iter().map(|x| { x.to_string() }).collect_vec())).unwrap();
            }
        }
    })
}

pub fn send_dns_query_packet(threads: usize, all_domains: &HashSet<String>, dns_servers: Vec<UpstreamServer>) -> HashMap<String, Vec<String>> {
    let mut dns_client = DNSClient::new(dns_servers);
    let mut file = std::fs::File::create("subdomain_ips.txt").unwrap();
    let (tx, rx) = channel();
    dns_client.set_timeout(Duration::from_millis(100));
    let pool = ThreadPool::new(threads);
    let mut s: HashMap<String, Vec<String>> = HashMap::new();
    all_domains.into_iter().for_each(|x| {
        let tx = tx.clone();
        let domain = String::from(x.to_string());
        run_start(&pool, dns_client.clone(), domain, tx);
    });
    drop(tx);
    rx.iter().for_each(|d| {
        println!("{} -> {:?}", d.0, d.1);
        let tmp_ips = d.1.iter().map(|x| { x.to_string() })
            .collect::<Vec<String>>().join(" ");
        let tmp_line = format!("{},{}\n", d.0, tmp_ips);
        file.write(tmp_line.as_bytes()).unwrap();
        s.insert(d.0, d.1);
    });
    pool.join();
    s
}