use std::{env, fs, io};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;

use chrono::prelude::*;
use clap::{App, AppSettings, Arg};
use dnsclient::UpstreamServer;
use headless_chrome::Browser;
use headless_chrome::protocol::browser::Bounds;
use headless_chrome::protocol::page::ScreenshotFormat;
use itertools::Itertools;
use reqwest::blocking::Client;

use crate::dnstools::{DEFAULT_DNS_SERVERS, get_fast_dns_list, send_dns_query_packet};
use crate::zoomeye::{IPHostInfo, IPHostInfoQuery, ZoomEye};
use crate::zoomeye::DomainQuery;

#[derive(Debug, Default)]
struct CommandLine {
    domain: String,
    dns_file: String,
    domain_file: String,
    thread_number: usize,
    work_dir: String,
    query_ip: bool,
    capture: bool,
    not_zoomeye: bool,
}

impl CommandLine {
    pub fn new() -> Self {
        Default::default()
    }
}


pub fn command_parse() {
    let mut cl = CommandLine::new();
    cl.thread_number = num_cpus::get();
    let matches = App::new("ct")
        .version("1.0.0")
        .about("Collect information tools about the target domain.")
        .author("Autor: rungobier@knownsec 404 team <rungobier@gmail.com>")
        .arg(Arg::with_name("domain")
            .help("Target domain name")
            .empty_values(false)
        ).arg(
        Arg::with_name("apikey")
            .long("init")
            .takes_value(true)
            .help("Initialize the ZoomEye api key ")
    ).arg(
        Arg::with_name("info")
            .short("i")
            .long("info")
            .required(false)
            .takes_value(false)
            .help("Get ZoomEye account base info")
    ).arg(
        Arg::with_name("dns-file")
            .short("s")
            .long("dns-dict")
            .takes_value(true)
            .required(false)
            .help("DNS Server list in a textual file.\nfile example...\n8.8.8.8\n1.1.1.1\n...")
    ).arg(
        Arg::with_name("T")
            .short("T")
            .required(false)
            .help("Network upload speed test.")
    ).arg(
        Arg::with_name("Z")
            .short("Z")
            .required(false)
            .help("Do not use zoomeye data")
    ).arg(
        Arg::with_name("thread-num")
            .short("t")
            .long("threads")
            .takes_value(true)
            .help("Maximum number of threads. Default number $CPU_NUM")
    ).arg(
        Arg::with_name("work-dir")
            .short("w")
            .long("work-dir")
            .takes_value(true)
            .help("Directory to save the results of tasks. Default [/tmp|$DESKTOP]/YYYYmmddHHMM_$DOMAIN")
    ).arg(Arg::with_name("domain-file")
        .short("d")
        .long("domain-dict")
        .required(false)
        .takes_value(true)
        .help("Domain dict list in a file.\nfile example....\nwww\nmail\ndev\n...")
    ).arg(Arg::with_name("query-ip")
        .short("q")
        .long("query-ip")
        .required(false)
        .takes_value(false)
        .help("Use zoomeye to query ip information")
    ).setting(AppSettings::ArgRequiredElseHelp)
        .get_matches();
    if matches.is_present("info") {
        let resource = ZoomEye::get_base_info();
        let info = format!("[+] Role: {}\
                           \n[+] Expired: {}\n[+] Free_quota: {}\
                           \n[+] Pay_quota: {}\n[+] Total_quota: {}",
                           resource.data.user_info.role,
                           resource.data.user_info.expired_at,
                           resource.data.quota_info.remain_free_quota,
                           resource.data.quota_info.remain_pay_quota,
                           resource.data.quota_info.remain_total_quota);
        println!("{}", info);
        return;
    }
    if matches.is_present("Z") {
        cl.not_zoomeye = true
    }
    if matches.is_present("T") {
        let (upload_bps, download_bps) = speedtest();
        println!("\nNetwork upload speed test {} Mbps.\
                  \nNetwork download speed test {} Mbps.\n", upload_bps/1024/1024,download_bps/1024/1024);
        return;
    }
    if let Some(domain_name) = matches.value_of("domain") {
        cl.domain = domain_name.to_string();
    }
    if  matches.is_present("query-ip") {
        cl.query_ip = true;
    }
    if let Some(work_dir) = matches.value_of("work-dir") {
        cl.work_dir = work_dir.to_string();
    } else {
        let dt = Local::now();
        let tmp_dir;
        if std::env::consts::OS.eq("windows") {
            tmp_dir = dirs::desktop_dir().unwrap().display().to_string();
        } else {
            tmp_dir = "/tmp".to_string();
        }
        cl.work_dir = format!("{}/{}_{}",
                              tmp_dir,
                              dt.format("%Y%m%d%H%M").to_string(),
                              cl.domain
        );
    }
    if let Some(dns_file) = matches.value_of("dns-file") {
        cl.dns_file = dns_file.to_string();
    }
    if let Some(domain_file) = matches.value_of("domain-file") {
        cl.domain_file = domain_file.to_string();
    }
    if let Some(apikey) = matches.value_of("apikey") {
        ZoomEye::init(apikey.to_string());
        return;
    }
    if let Some(num) = matches.value_of("thread-num") {
        cl.thread_number = num.to_string().parse().unwrap();
    }
    run(&mut cl);
}

fn run(cl: &mut CommandLine) {
    let mut domainquery = DomainQuery::new();
    let mut all_hs_subdomain = HashSet::new();
    let mut all_hs_dns_servers = HashSet::new();

    let convert_sh_filename = "convert2png.sh";
    let convert_bat_filename = "convert2png.bat";
    let ip_gv_filename = "ip_graph.gv";
    let domain_gv_filename = "domain_graph.gv";

    //建立工作目录，并切换当前工作目录
    fs::create_dir_all(cl.work_dir.clone()).unwrap();
    let file_path = cl.work_dir.clone();
    let work_dir = Path::new(&file_path);
    if env::set_current_dir(&work_dir).is_ok() {
        fs::create_dir_all("./img/").unwrap();
        fs::create_dir_all("./data/").unwrap();
        println!("Successfully changed working directory to {}!", work_dir.display());
    }

    //如果使用zoomeye，那么获取用户信息,核实用户信息数据权限
    if !cl.not_zoomeye {
        let base_info = ZoomEye::get_base_info();
        let tmp_total_quota = base_info.data.quota_info.remain_total_quota;
        if tmp_total_quota == 0 {
            cl.not_zoomeye = true;
        } else {
            //获取zoomeye上相关目标域名的子域名信息
            let query_str = format!("https://api.zoomeye.org/domain/search?q={}&s=20000&type=1", cl.domain);
            domainquery.query_str = query_str;
            domainquery.query();
            if domainquery.data.total > 0 {
                domainquery.data.list.iter()
                    .for_each(|d| { all_hs_subdomain.insert(d.name.to_string()); });
            }
            println!("ZoomEye subdomain: {} ", all_hs_subdomain.len());
        }
    }

    //合并根据字典生成的子域名
    if !cl.domain_file.is_empty() {
        let subdomain = get_dict_from_file(cl.domain_file.as_str());
        subdomain.iter().for_each(|sd| {
            let tmp_subdomain = format!("{}.{}", sd, cl.domain);
            all_hs_subdomain.insert(tmp_subdomain);
        });
    }

    if all_hs_subdomain.len() == 0 {
        return;
    }

    //获取指定的文件内的DNS服务器清单
    if !cl.dns_file.is_empty() {
        let dns_servers = get_dict_from_file(cl.dns_file.as_str());
        dns_servers.iter().for_each(|ds| {
            all_hs_dns_servers.insert(ds.to_string());
        });
    }
    //合并常用DNS服务器
    DEFAULT_DNS_SERVERS.iter()
        .for_each(|s| {
            all_hs_dns_servers.insert(s.to_string());
        });
    println!("total upstream DNS server: {}", all_hs_dns_servers.len());


    //对dns查询以及相关服务器进行速度测试，并只取20台作为dns查询服务器
    let speed_dns = get_fast_dns_list(&all_hs_dns_servers, cl.thread_number);
    let dns_top20 = speed_dns.into_iter()
        .take(20)
        .map(|(a, _)| { a })
        .collect::<Vec<_>>();

    //开始子域名爆破
    let dns_servers = dns_top20.iter().map(|s| {
        UpstreamServer::new(
            SocketAddr::from_str(s).unwrap()
        )
    }).collect::<Vec<UpstreamServer>>();

    let sub_domain_result = send_dns_query_packet(cl.thread_number, &all_hs_subdomain, dns_servers);
    //写入爆破出的子域名文件以及以域名为中心纬度写出graphviz文件
    let mut graph_file = std::fs::File::create(domain_gv_filename).unwrap();
    let domain_graph_lines = sub_domain_result.iter().map(move |x| {
        let tmp_ips = x.1.iter()
            .map(|x| { x.to_string() })
            .collect::<Vec<String>>().join(" ");
        format!("{{\"{}\"}}->{{{}}};\n",
                x.0,
                tmp_ips.split(" ").into_iter().map(|x| format!("\"{}\"", x))
                    .collect::<Vec<String>>().join(" ")
        )
    }).collect::<Vec<String>>();

    graph_file.write(format!("digraph {} {{ \n {} }}\n", cl.domain.replace(".", "_"), domain_graph_lines.join("")).as_bytes()).unwrap();
    //以IP为中心纬度写入graphviz文件
    //清理出所有相关的IP信息，并将IP转化成为zoomeye的检索dork
    let mut graph_file = std::fs::File::create(ip_gv_filename).unwrap();
    let mut all_subdomain_ips = HashSet::new();
    let ip_domains = sub_domain_result.iter().map(|x| {
        let mut tmp_ip_domain = String::new();
        for ip in x.1.iter() {
            all_subdomain_ips.insert(format!("ip:{}", (*ip)));
            tmp_ip_domain.push_str(format!("{{\"{}\"}}->{{\"{}\"}};\n", (*ip).to_string(), x.0).as_str());
        }
        tmp_ip_domain
    }).collect::<Vec<String>>();
    graph_file.write(format!("digraph {} {{ \n {}  }}\n",
                             cl.domain.replace(".", "_"),
                             ip_domains.join(""),
    ).as_bytes()).unwrap();

    let mut convert_sh = std::fs::File::create(convert_sh_filename).unwrap();
    let mut convert_bat = std::fs::File::create(convert_bat_filename).unwrap();
    let def_template = format!("sfdp -Tpng {} -O \nsfdp -Tpng {} -O\n", domain_gv_filename, ip_gv_filename);
    let sh_template = format!("#!/bin/sh\n{}", def_template);
    let bat_template = format!("@echo off\n{}", def_template);
    convert_sh.write_all(sh_template.as_bytes()).unwrap();
    convert_bat.write_all(bat_template.as_bytes()).unwrap();


    //以及相关报文数据,解析出的子域名对应IP，以及相关端口
    if !cl.not_zoomeye && cl.query_ip {
        println!("Start get zoomeye ip data...");
        let all_ip_query_result = all_subdomain_ips.iter().map(|ipdork| {
            let mut iq = IPHostInfoQuery::new();
            iq.query_str = format!("https://api.zoomeye.org/host/search?query={}", ipdork);
            iq.query();
            iq.data
        }).collect::<Vec<IPHostInfo>>();

        //针对ip加端口进行截图及页面文件抓取
        let mut ip_ports = HashMap::new();

        //根据查询IP所得结果写入文件
        all_ip_query_result.iter().for_each(|iphi| {
            if iphi.matches.len() > 0  {
                let ip_address = iphi.matches.get(0).unwrap().ip.clone();
                let tmp_file = format!("./data/{}.json", ip_address);
                let mut file = std::fs::File::create(tmp_file).unwrap();
                file.write(serde_json::to_string(iphi).unwrap().as_bytes()).unwrap();
                ip_ports.insert(ip_address, iphi.matches.iter().map(|i| {
                    //简单对banner进行过滤， 为后续的抓取数据铺垫
                    if i.portinfo.banner.contains("<title>") && !i.portinfo.banner.contains("Bad Request") {
                        (i.portinfo.port, 1)
                    } else {
                        (i.portinfo.port, 0)
                    }
                }).collect::<Vec<(u32, u32)>>());
            }
        });
        cl.capture = false;
        //抓取目标子域名下的IP截图
        if cl.capture {
            ip_ports.into_iter().for_each(|k| {
                k.1.iter().for_each(|(p, v)| {
                    if *v == 1 {
                        let tmp_ip_port = format!("{}:{}", k.0, p);
                        println!("{}", tmp_ip_port);
                        get_webpage_screenshot(tmp_ip_port);
                    }
                });
            });
        }
    }


    //TODO: 后续的数据处理可以使用lua进行扩展
}
/*
#[allow(dead_code)]
fn run_lua() {
    let mut file = std::fs::File::open("/tmp/test.lua").unwrap();
    let mut contents = String::new();
    let _ = file.read_to_string(&mut contents).unwrap();
    let lua = Lua::new();
    let globals = lua.globals();
    globals.set("gstr", "hello").unwrap();
    lua.load(&contents).exec().unwrap();
    let lua_version: String = globals.get("_VERSION").unwrap();
    for _ in 1..10 {
        println!("###################################");
    }
    println!("Hello, world! Lua version: {}", lua_version);
    let path = dirs::home_dir().unwrap().as_path().to_str().unwrap().to_string();
    println!("HOME is : {}", path);
}
*/

fn get_dict_from_file(filepath: &str) -> Vec<String> {
    let file = File::open(filepath).unwrap();
    let bf = BufReader::new(file);
    let all_lines: Vec<String> = bf.lines().collect::<Result<_, _>>().unwrap();
    all_lines
}

fn get_webpage_screenshot(ip_port: String) {
    let (_, port) = ip_port.splitn(2, ":").collect_tuple().unwrap();
    let tmp_port = String::from(port).parse::<u32>().unwrap();
    let start;
    if tmp_port == 443 || tmp_port == 8443 {
        start = String::from("https://".to_owned() + ip_port.as_str());
    } else {
        start = String::from("http://".to_owned() + ip_port.as_str());
    }

    let file_name = format!("./img/{}.png", ip_port.replace(":", "_"));
    let mut file = File::create(file_name).unwrap();

    let browser = Browser::default().unwrap();
    let tab = browser.wait_for_initial_tab().unwrap();
    tab.set_bounds(Bounds::Normal {
        left: Some(0),
        top: Some(0),
        width: Some(1920),
        height: Some(1080),
    }).unwrap();
    tab.navigate_to(start.as_str()).unwrap();
    tab.wait_until_navigated().unwrap();

    let png_data = tab.capture_screenshot(ScreenshotFormat::PNG, None, true).unwrap();
    file.write(png_data.as_slice()).unwrap();
}

#[allow(dead_code)]
fn get_webpage_body(url_str: &str) -> String {
    let client = Client::builder().build().unwrap();
    let res = client.get(url_str).send().unwrap();
    res.text().unwrap()
}

fn speedtest() -> (usize, usize) {
    let mut config = speedtest_rs::speedtest::get_configuration().unwrap();
    let server_list_sorted;
    let server_list = speedtest_rs::speedtest::get_server_list_with_config(&config).unwrap();
    server_list_sorted = server_list.servers_sorted_by_distance(&config);
    let latency_test_result = speedtest_rs::speedtest::get_best_server_based_on_latency(&server_list_sorted[..]).unwrap();
    let best_server = latency_test_result.server;
    let inner_upload_measurement=
        speedtest_rs::speedtest::test_upload_with_progress_and_config(best_server, || {
            print!(".");
            io::stdout().flush().unwrap();
        }, &config).expect("Upload speedtest error.");
    let inner_download_measurement = speedtest_rs::speedtest::test_download_with_progress_and_config(best_server, ||{
        print!(".");
        io::stdout().flush().unwrap();
    }, &mut config).expect("Download speedtest error.");
    (inner_upload_measurement.bps_f64() as usize, inner_download_measurement.bps_f64() as usize)
}
