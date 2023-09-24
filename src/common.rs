use std::{env, fs, io};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;

use chrono::prelude::*;
use clap::{App, AppSettings, Arg};
use commonregex::{ips, ipv6s};
use dnsclient::UpstreamServer;
use headless_chrome::Browser;
use headless_chrome::protocol::browser::Bounds;
use headless_chrome::protocol::page::ScreenshotFormat;
use itertools::Itertools;
use reqwest::blocking::Client;
use tldextract::{TldExtractor, TldOption};

use crate::dnstools::{DEFAULT_DNS_SERVERS, get_fast_dns_list, send_dns_query_packet};
use crate::zoomeye::{IPHostInfo, IPHostInfoQuery, ZoomEye};
use crate::zoomeye::DomainQuery;

//Extended analysis 扩展分析
//Extended filtering 扩展过滤
#[derive(Debug, Default)]
struct CommandLine {
    domain: String,
    dns_file: String,
    domain_file: String,
    thread_number: usize,
    query_number: usize,
    work_dir: String,
    query_ip: bool,
    cidr: bool,
    capture: bool,
    extended_analysis: bool,
    extended_filtering: HashSet<String>,
    not_zoomeye: bool,
}

impl CommandLine {
    pub fn new() -> Self {
        Default::default()
    }
}


pub fn command_parse() {
    let mut cl = CommandLine::new();
    //初始化过滤cdn信息
    cl.extended_filtering.insert("15cdn.com".to_string());
    cl.extended_filtering.insert("tzcdn.cn".to_string());
    cl.extended_filtering.insert("cedexis.net".to_string());
    cl.extended_filtering.insert("cdxcn.cn".to_string());
    cl.extended_filtering.insert("qhcdn.com".to_string());
    cl.extended_filtering.insert("qh-cdn.com".to_string());
    cl.extended_filtering.insert("qihucdn.com".to_string());
    cl.extended_filtering.insert("360cdn.com".to_string());
    cl.extended_filtering.insert("360cloudwaf.com".to_string());
    cl.extended_filtering.insert("360anyu.com".to_string());
    cl.extended_filtering.insert("360safedns.com".to_string());
    cl.extended_filtering.insert("360wzws.com".to_string());
    cl.extended_filtering.insert("akamai.net".to_string());
    cl.extended_filtering.insert("akamaiedge.net".to_string());
    cl.extended_filtering.insert("ytcdn.net".to_string());
    cl.extended_filtering.insert("edgesuite.net".to_string());
    cl.extended_filtering.insert("akamaitech.net".to_string());
    cl.extended_filtering.insert("akamaitechnologies.com".to_string());
    cl.extended_filtering.insert("edgekey.net".to_string());
    cl.extended_filtering.insert("tl88.net".to_string());
    cl.extended_filtering.insert("cloudfront.net".to_string());
    cl.extended_filtering.insert("worldcdn.net".to_string());
    cl.extended_filtering.insert("worldssl.net".to_string());
    cl.extended_filtering.insert("cdn77.org".to_string());
    cl.extended_filtering.insert("panthercdn.com".to_string());
    cl.extended_filtering.insert("cdnga.net".to_string());
    cl.extended_filtering.insert("cdngc.net".to_string());
    cl.extended_filtering.insert("gccdn.net".to_string());
    cl.extended_filtering.insert("gccdn.cn".to_string());
    cl.extended_filtering.insert("akamaized.net".to_string());
    cl.extended_filtering.insert("126.net".to_string());
    cl.extended_filtering.insert("163jiasu.com".to_string());
    cl.extended_filtering.insert("amazonaws.com".to_string());
    cl.extended_filtering.insert("cdn77.net".to_string());
    cl.extended_filtering.insert("cdnify.io".to_string());
    cl.extended_filtering.insert("cdnsun.net".to_string());
    cl.extended_filtering.insert("bdydns.com".to_string());
    cl.extended_filtering.insert("ccgslb.com.cn".to_string());
    cl.extended_filtering.insert("ccgslb.net".to_string());
    cl.extended_filtering.insert("ccgslb.com".to_string());
    cl.extended_filtering.insert("ccgslb.cn".to_string());
    cl.extended_filtering.insert("c3cache.net".to_string());
    cl.extended_filtering.insert("c3dns.net".to_string());
    cl.extended_filtering.insert("chinacache.net".to_string());
    cl.extended_filtering.insert("wswebcdn.com".to_string());
    cl.extended_filtering.insert("lxdns.com".to_string());
    cl.extended_filtering.insert("wswebpic.com".to_string());
    cl.extended_filtering.insert("cloudflare.net".to_string());
    cl.extended_filtering.insert("akadns.net".to_string());
    cl.extended_filtering.insert("chinanetcenter.com".to_string());
    cl.extended_filtering.insert("customcdn.com.cn".to_string());
    cl.extended_filtering.insert("customcdn.cn".to_string());
    cl.extended_filtering.insert("51cdn.com".to_string());
    cl.extended_filtering.insert("wscdns.com".to_string());
    cl.extended_filtering.insert("cdn20.com".to_string());
    cl.extended_filtering.insert("wsdvs.com".to_string());
    cl.extended_filtering.insert("wsglb0.com".to_string());
    cl.extended_filtering.insert("speedcdns.com".to_string());
    cl.extended_filtering.insert("wtxcdn.com".to_string());
    cl.extended_filtering.insert("wsssec.com".to_string());
    cl.extended_filtering.insert("fastly.net".to_string());
    cl.extended_filtering.insert("fastlylb.net".to_string());
    cl.extended_filtering.insert("hwcdn.net".to_string());
    cl.extended_filtering.insert("incapdns.net".to_string());
    cl.extended_filtering.insert("kxcdn.com.".to_string());
    cl.extended_filtering.insert("lswcdn.net".to_string());
    cl.extended_filtering.insert("mwcloudcdn.com".to_string());
    cl.extended_filtering.insert("mwcname.com".to_string());
    cl.extended_filtering.insert("azureedge.net".to_string());
    cl.extended_filtering.insert("msecnd.net".to_string());
    cl.extended_filtering.insert("mschcdn.com".to_string());
    cl.extended_filtering.insert("v0cdn.net".to_string());
    cl.extended_filtering.insert("azurewebsites.net".to_string());
    cl.extended_filtering.insert("azurewebsites.windows.net".to_string());
    cl.extended_filtering.insert("trafficmanager.net".to_string());
    cl.extended_filtering.insert("cloudapp.net".to_string());
    cl.extended_filtering.insert("chinacloudsites.cn".to_string());
    cl.extended_filtering.insert("spdydns.com".to_string());
    cl.extended_filtering.insert("jiashule.com".to_string());
    cl.extended_filtering.insert("jiasule.org".to_string());
    cl.extended_filtering.insert("365cyd.cn".to_string());
    cl.extended_filtering.insert("huaweicloud.com".to_string());
    cl.extended_filtering.insert("cdnhwc1.com".to_string());
    cl.extended_filtering.insert("cdnhwc2.com".to_string());
    cl.extended_filtering.insert("cdnhwc3.com".to_string());
    cl.extended_filtering.insert("dnion.com".to_string());
    cl.extended_filtering.insert("ewcache.com".to_string());
    cl.extended_filtering.insert("globalcdn.cn".to_string());
    cl.extended_filtering.insert("tlgslb.com".to_string());
    cl.extended_filtering.insert("fastcdn.com".to_string());
    cl.extended_filtering.insert("flxdns.com".to_string());
    cl.extended_filtering.insert("dlgslb.cn".to_string());
    cl.extended_filtering.insert("newdefend.cn".to_string());
    cl.extended_filtering.insert("ffdns.net".to_string());
    cl.extended_filtering.insert("aocdn.com".to_string());
    cl.extended_filtering.insert("bsgslb.cn".to_string());
    cl.extended_filtering.insert("qingcdn.com".to_string());
    cl.extended_filtering.insert("bsclink.cn".to_string());
    cl.extended_filtering.insert("trpcdn.net".to_string());
    cl.extended_filtering.insert("anquan.io".to_string());
    cl.extended_filtering.insert("cloudglb.com".to_string());
    cl.extended_filtering.insert("fastweb.com".to_string());
    cl.extended_filtering.insert("fastwebcdn.com".to_string());
    cl.extended_filtering.insert("cloudcdn.net".to_string());
    cl.extended_filtering.insert("fwcdn.com".to_string());
    cl.extended_filtering.insert("fwdns.net".to_string());
    cl.extended_filtering.insert("hadns.net".to_string());
    cl.extended_filtering.insert("hacdn.net".to_string());
    cl.extended_filtering.insert("cachecn.com".to_string());
    cl.extended_filtering.insert("qingcache.com".to_string());
    cl.extended_filtering.insert("qingcloud.com".to_string());
    cl.extended_filtering.insert("frontwize.com".to_string());
    cl.extended_filtering.insert("msscdn.com".to_string());
    cl.extended_filtering.insert("800cdn.com".to_string());
    cl.extended_filtering.insert("tbcache.com".to_string());
    cl.extended_filtering.insert("aliyun-inc.com".to_string());
    cl.extended_filtering.insert("aliyuncs.com".to_string());
    cl.extended_filtering.insert("alikunlun.net".to_string());
    cl.extended_filtering.insert("alikunlun.com".to_string());
    cl.extended_filtering.insert("alicdn.com".to_string());
    cl.extended_filtering.insert("aligaofang.com".to_string());
    cl.extended_filtering.insert("yundunddos.com".to_string());
    cl.extended_filtering.insert("kunlun(.*.to_string()).com".to_string());
    cl.extended_filtering.insert("cdngslb.com".to_string());
    cl.extended_filtering.insert("yunjiasu-cdn.net".to_string());
    cl.extended_filtering.insert("momentcdn.com".to_string());
    cl.extended_filtering.insert("aicdn.com".to_string());
    cl.extended_filtering.insert("qbox.me".to_string());
    cl.extended_filtering.insert("qiniu.com".to_string());
    cl.extended_filtering.insert("qiniudns.com".to_string());
    cl.extended_filtering.insert("jcloudcs.com".to_string());
    cl.extended_filtering.insert("jdcdn.com".to_string());
    cl.extended_filtering.insert("qianxun.com".to_string());
    cl.extended_filtering.insert("jcloudlb.com".to_string());
    cl.extended_filtering.insert("jcloud-cdn.com".to_string());
    cl.extended_filtering.insert("maoyun.tv".to_string());
    cl.extended_filtering.insert("maoyundns.com".to_string());
    cl.extended_filtering.insert("xgslb.net".to_string());
    cl.extended_filtering.insert("ucloud.cn".to_string());
    cl.extended_filtering.insert("ucloud.com.cn".to_string());
    cl.extended_filtering.insert("cdndo.com".to_string());
    cl.extended_filtering.insert("zenlogic.net".to_string());
    cl.extended_filtering.insert("ogslb.com".to_string());
    cl.extended_filtering.insert("uxengine.net".to_string());
    cl.extended_filtering.insert("tan14.net".to_string());
    cl.extended_filtering.insert("verycloud.cn".to_string());
    cl.extended_filtering.insert("verycdn.net".to_string());
    cl.extended_filtering.insert("verygslb.com".to_string());
    cl.extended_filtering.insert("xundayun.cn".to_string());
    cl.extended_filtering.insert("xundayun.com".to_string());
    cl.extended_filtering.insert("speedycloud.cc".to_string());
    cl.extended_filtering.insert("mucdn.net".to_string());
    cl.extended_filtering.insert("nucdn.net".to_string());
    cl.extended_filtering.insert("alphacdn.net".to_string());
    cl.extended_filtering.insert("systemcdn.net".to_string());
    cl.extended_filtering.insert("edgecastcdn.net".to_string());
    cl.extended_filtering.insert("zetacdn.net".to_string());
    cl.extended_filtering.insert("coding.io".to_string());
    cl.extended_filtering.insert("coding.me".to_string());
    cl.extended_filtering.insert("gitlab.io".to_string());
    cl.extended_filtering.insert("github.io".to_string());
    cl.extended_filtering.insert("herokuapp.com".to_string());
    cl.extended_filtering.insert("googleapis.com".to_string());
    cl.extended_filtering.insert("netdna.com".to_string());
    cl.extended_filtering.insert("netdna-cdn.com".to_string());
    cl.extended_filtering.insert("netdna-ssl.com".to_string());
    cl.extended_filtering.insert("cdntip.com".to_string());
    cl.extended_filtering.insert("dnsv1.com".to_string());
    cl.extended_filtering.insert("tencdns.net".to_string());
    cl.extended_filtering.insert("dayugslb.com".to_string());
    cl.extended_filtering.insert("tcdnvod.com".to_string());
    cl.extended_filtering.insert("tdnsv5.com".to_string());
    cl.extended_filtering.insert("ksyuncdn.com".to_string());
    cl.extended_filtering.insert("ks-cdn.com".to_string());
    cl.extended_filtering.insert("ksyuncdn-k1.com".to_string());
    cl.extended_filtering.insert("netlify.com".to_string());
    cl.extended_filtering.insert("zeit.co".to_string());
    cl.extended_filtering.insert("zeit-cdn.net".to_string());
    cl.extended_filtering.insert("b-cdn.net".to_string());
    cl.extended_filtering.insert("lsycdn.com".to_string());
    cl.extended_filtering.insert("scsdns.com".to_string());
    cl.extended_filtering.insert("quic.cloud".to_string());
    cl.extended_filtering.insert("flexbalancer.net".to_string());
    cl.extended_filtering.insert("gcdn.co".to_string());
    cl.extended_filtering.insert("sangfordns.com".to_string());
    cl.extended_filtering.insert("stspg-customer.com".to_string());
    cl.extended_filtering.insert("turbobytes.net".to_string());
    cl.extended_filtering.insert("turbobytes-cdn.com".to_string());
    cl.extended_filtering.insert("att-dsa.net".to_string());
    cl.extended_filtering.insert("azioncdn.net".to_string());
    cl.extended_filtering.insert("belugacdn.com".to_string());
    cl.extended_filtering.insert("cachefly.net".to_string());
    cl.extended_filtering.insert("inscname.net".to_string());
    cl.extended_filtering.insert("insnw.net".to_string());
    cl.extended_filtering.insert("internapcdn.net".to_string());
    cl.extended_filtering.insert("footprint.net".to_string());
    cl.extended_filtering.insert("llnwi.net".to_string());
    cl.extended_filtering.insert("llnwd.net".to_string());
    cl.extended_filtering.insert("unud.net".to_string());
    cl.extended_filtering.insert("lldns.net".to_string());
    cl.extended_filtering.insert("stackpathdns.com".to_string());
    cl.extended_filtering.insert("stackpathcdn.com".to_string());
    cl.extended_filtering.insert("mncdn.com".to_string());
    cl.extended_filtering.insert("rncdn1.com".to_string());
    cl.extended_filtering.insert("simplecdn.net".to_string());
    cl.extended_filtering.insert("swiftserve.com".to_string());
    cl.extended_filtering.insert("bitgravity.com".to_string());
    cl.extended_filtering.insert("zenedge.net".to_string());
    cl.extended_filtering.insert("biliapi.com".to_string());
    cl.extended_filtering.insert("hdslb.net".to_string());
    cl.extended_filtering.insert("hdslb.com".to_string());
    cl.extended_filtering.insert("xwaf.cn".to_string());
    cl.extended_filtering.insert("shifen.com".to_string());
    cl.extended_filtering.insert("sinajs.cn".to_string());
    cl.extended_filtering.insert("tencent-cloud.net".to_string());
    cl.extended_filtering.insert("elemecdn.com".to_string());
    cl.extended_filtering.insert("sinaedge.com".to_string());
    cl.extended_filtering.insert("sina.com.cn".to_string());
    cl.extended_filtering.insert("sinacdn.com".to_string());
    cl.extended_filtering.insert("sinasws.com".to_string());
    cl.extended_filtering.insert("saebbs.com".to_string());
    cl.extended_filtering.insert("websitecname.cn".to_string());
    cl.extended_filtering.insert("cdncenter.cn".to_string());
    cl.extended_filtering.insert("vhostgo.com".to_string());
    cl.extended_filtering.insert("jsd.cc".to_string());
    cl.extended_filtering.insert("powercdn.cn".to_string());
    cl.extended_filtering.insert("21vokglb.cn".to_string());
    cl.extended_filtering.insert("21vianet.com.cn".to_string());
    cl.extended_filtering.insert("21okglb.cn".to_string());
    cl.extended_filtering.insert("21speedcdn.com".to_string());
    cl.extended_filtering.insert("21cvcdn.com".to_string());
    cl.extended_filtering.insert("okcdn.com".to_string());
    cl.extended_filtering.insert("okglb.com".to_string());
    cl.extended_filtering.insert("cdnetworks.net".to_string());
    cl.extended_filtering.insert("txnetworks.cn".to_string());
    cl.extended_filtering.insert("cdnnetworks.com".to_string());
    cl.extended_filtering.insert("txcdn.cn".to_string());
    cl.extended_filtering.insert("cdnunion.net".to_string());
    cl.extended_filtering.insert("cdnunion.com".to_string());
    cl.extended_filtering.insert("mygslb.com".to_string());
    cl.extended_filtering.insert("cdnudns.com".to_string());
    cl.extended_filtering.insert("sprycdn.com".to_string());
    cl.extended_filtering.insert("chuangcdn.com".to_string());
    cl.extended_filtering.insert("aocde.com".to_string());
    cl.extended_filtering.insert("ctxcdn.cn".to_string());
    cl.extended_filtering.insert("yfcdn.net".to_string());
    cl.extended_filtering.insert("mmycdn.cn".to_string());
    cl.extended_filtering.insert("chinamaincloud.com".to_string());
    cl.extended_filtering.insert("cnispgroup.com".to_string());
    cl.extended_filtering.insert("cdnle.com".to_string());
    cl.extended_filtering.insert("gosuncdn.com".to_string());
    cl.extended_filtering.insert("mmtrixopt.com".to_string());
    cl.extended_filtering.insert("cloudfence.cn".to_string());
    cl.extended_filtering.insert("ngaagslb.cn".to_string());
    cl.extended_filtering.insert("p2cdn.com".to_string());
    cl.extended_filtering.insert("00cdn.com".to_string());
    cl.extended_filtering.insert("sankuai.com".to_string());
    cl.extended_filtering.insert("lccdn.org".to_string());
    cl.extended_filtering.insert("nscloudwaf.com".to_string());
    cl.extended_filtering.insert("2cname.com".to_string());
    cl.extended_filtering.insert("ucloudgda.com".to_string());
    cl.extended_filtering.insert("google.com".to_string());
    cl.extended_filtering.insert("1e100.net".to_string());
    cl.extended_filtering.insert("ncname.com".to_string());
    cl.extended_filtering.insert("alipaydns.com".to_string());
    cl.extended_filtering.insert("wscloudcdn.com".to_string());
    ////////////////////////////////
    cl.thread_number = num_cpus::get();
    let matches = App::new("ct")
        .version("1.0.9")
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
        Arg::with_name("E")
            .short("E")
            .required(false)
            .help("Extended analysis domain")
    ).arg(
        Arg::with_name("filter-domains")
            .short("F")
            .takes_value(true)
            .help("Extended filter domain list.\nExample of extended filtering domain name list: knownsec.com,jiasule.com,365cyd.com...")
    ).arg(
        Arg::with_name("thread-num")
            .short("t")
            .long("threads")
            .takes_value(true)
            .help("Maximum number of threads. Default number $CPU_NUM")
    ).arg(
        Arg::with_name("query-num")
            .long("query-num")
            .takes_value(true)
            .help("Maximum number of zoomeye query. Default query number 100")
    ).arg(
        Arg::with_name("cidr")
            .long("cidr")
            .short("C")
            .required(false)
            .help("Convert the IP related to the target domain name to cidr for extended search. Default is false.")
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
    if matches.is_present("E") {
        cl.extended_analysis = true;
    }

    if let Some(ex_filter) = matches.value_of("filter-domains") {
        ex_filter.split(',').for_each(|x| {
            cl.extended_filtering.insert(x.to_string());
        });
    }
    if matches.is_present("T") {
        let (upload_bps, download_bps) = speedtest();
        println!("\nNetwork upload speed test {} Mbps.\
                  \nNetwork download speed test {} Mbps.\n", upload_bps / (1024 * 1024), download_bps / (1024 * 1024));
        return;
    }
    if let Some(domain_name) = matches.value_of("domain") {
        cl.domain = domain_name.to_string();
        cl.extended_filtering.insert(cl.domain.clone());
    }
    if matches.is_present("query-ip") {
        cl.query_ip = true;
    } else {
        cl.query_ip = false;
    }
    if let Some(qnum) = matches.value_of("query-num") {
        cl.query_number = qnum.to_string().parse().unwrap();
    } else {
        cl.query_number = 100;
    }

    if matches.is_present("cidr") {
        cl.cidr = true;
    } else {
        cl.cidr = false;
    }

    if let Some(work_dir) = matches.value_of("work-dir") {
        cl.work_dir = work_dir.to_string();
    } else {
        let dt = Local::now();
        let tmp_dir;
        if env::consts::OS.eq("windows") {
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
    cl.cidr = false;
    if cl.domain.is_empty() {
        return;
    }
    run(&mut cl);
}

fn run(cl: &mut CommandLine) {
    let mut domainquery = DomainQuery::new();
    let mut all_hs_subdomain = HashSet::new();
    let mut all_hs_dns_servers = HashSet::new();
    let mut sub_domain_result = HashMap::new();

    let convert_sh_filename = "convert2png.sh";
    let all_subdomains = "all_subdomains.csv";
    let convert_bat_filename = "convert2png.bat";
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
                    .for_each(|d| {
                        if d.ip.len() > 0 {
                            sub_domain_result.insert(d.name.to_string(), d.ip.clone());
                        } else {
                            all_hs_subdomain.insert(d.name.to_string());
                        }
                    });
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

    let tmp_sub_domain_result = send_dns_query_packet(cl.thread_number, &all_hs_subdomain, dns_servers);
    sub_domain_result.extend(tmp_sub_domain_result);

    //清理出所有相关的IP信息，并将IP转化成为zoomeye的检索dork
    let mut all_ips  = HashSet::new();
    let mut second_subdomains = HashSet::new();
    sub_domain_result.iter().filter(|x| !cl.extended_filtering.contains(x.0)).for_each(|x| {
        for ip in x.1.iter() {
            all_ips.insert((*ip).to_string());
            let query_str = format!("https://api.zoomeye.org/domain/search?q={}&s={}&type=1", *ip, cl.query_number);
            domainquery.query_str = query_str;
            domainquery.query();
            if domainquery.data.total > 0 {
                domainquery.data.list.iter()
                    .for_each(|d| {
                        //筛除IP地址
                        let sd = get_root_domain(&d.name);
                        if !cl.extended_filtering.contains(&sd) {
                            second_subdomains.insert(sd);
                        }
                    });
            }
        }
    });


    if cl.extended_analysis {
        // 需要过滤查询结果中的ip地址以及已经存在的域名
        all_ips.iter().filter(|x| !cl.extended_filtering.contains(*x)).for_each(|ip| {
            let query_str = format!("https://api.zoomeye.org/domain/search?q={}&s={}&type=1", *ip, cl.query_number);
            domainquery.query_str = query_str;
            domainquery.query();
            if domainquery.data.total > 0 {
                domainquery.data.list.iter()
                    .for_each(|d| {
                        //筛除IP地址
                        let sd = get_root_domain(&d.name);
                        if !cl.extended_filtering.contains(&sd) {
                            sub_domain_result.insert(d.name.to_string(), d.ip.clone());
                            second_subdomains.insert(sd);
                        }
                    });
            }
        });

        second_subdomains.iter().filter(|x| !cl.extended_filtering.contains(*x)).for_each(|d| {
            let query_str = format!("https://api.zoomeye.org/domain/search?q={}&s={}&type=1", *d, cl.query_number);
            domainquery.query_str = query_str;
            domainquery.query();
            if domainquery.data.total > 0 {
                domainquery.data.list.iter()
                    .for_each(|dt| {
                        dt.ip.iter().for_each(|ip| {
                            sub_domain_result.insert(dt.name.to_string(), dt.ip.clone());
                            all_ips.insert(ip.to_string());
                        });
                    });
            }
        });
    }
    if cl.cidr {
        let mut cidr_search = HashSet::new();
        all_ips.iter().for_each(|ip| {
            let mut ip_split = ip.split(".").collect_vec();
            ip_split[3] = "1/24";
            cidr_search.insert(ip_split.join("."));
        });
        cidr_search.iter().for_each(|cidr_key| {
            let query_str = format!("https://api.zoomeye.org/domain/search?q={}&s={}&type=1", cidr_key, cl.query_number);
            domainquery.query_str = query_str;
            domainquery.query();
            if domainquery.data.total > 0 {
                domainquery.data.list.iter().for_each(|d| {
                    let sd = get_root_domain(&d.name);
                    if !cl.extended_filtering.contains(&sd) {
                        sub_domain_result.insert(d.name.clone(), d.ip.clone());
                    }
                });
            }
        })
    }

    let mut all_second_subdomains = File::create(all_subdomains).unwrap();
    all_second_subdomains.write(format!("\"subdomain\",\"ips\"\n").as_bytes()).unwrap();
    sub_domain_result.iter().for_each(|s| {
        all_second_subdomains.write(format!("\"{}\",\"[{}]\"\n", s.0, s.1.join(",").to_string()).as_bytes()).unwrap();
    });

    ////////////////////////////////////////////////////////////////////////////////
    //此处需要优化考虑是否需要构造出graphviz文件
    //写入爆破出的子域名文件以及以域名为中心纬度写出graphviz文件
    let mut graph_file = File::create(domain_gv_filename).unwrap();
    let mut domain_graph_lines = Vec::new();
    sub_domain_result.iter().for_each(|x| {
        x.1.iter().for_each(|ip| {
            domain_graph_lines.push(format!("{{\"{}\"}}->{{\"{}\"}};\n", x.0.as_str(), ip.as_str()));
        });
    });
    graph_file.write(format!("digraph {} {{ \n {} }}\n", cl.domain.replace(".", "_"), domain_graph_lines.join("")).as_bytes()).unwrap();
    ////////////////////////////////////////////////////////////////////////////////


    let mut convert_sh = File::create(convert_sh_filename).unwrap();
    let mut convert_bat = File::create(convert_bat_filename).unwrap();
    let def_template = format!("sfdp -Tpng {} -O \n", domain_gv_filename);
    let sh_template = format!("#!/bin/sh\n{}", def_template);
    let bat_template = format!("@echo off\n{}", def_template);
    convert_sh.write_all(sh_template.as_bytes()).unwrap();
    convert_bat.write_all(bat_template.as_bytes()).unwrap();

    
    //以及相关报文数据,解析出的子域名对应IP，以及相关端口
    if !cl.not_zoomeye && cl.query_ip {
        println!("Start get zoomeye ip data......");
        let all_ip_query_result = all_ips.iter().map(|ipdork| {
            let mut iq = IPHostInfoQuery::new();
            iq.query_str = format!("https://api.zoomeye.org/host/search?query=ip:{}", ipdork);
            iq.query();
            iq.data
        }).collect::<Vec<IPHostInfo>>();

        //针对ip加端口进行截图及页面文件抓取
        let mut ip_ports = HashMap::new();

        //根据查询IP所得结果写入文件
        all_ip_query_result.iter().for_each(|iphi| {
            if iphi.matches.len() > 0 {
                let ip_address = iphi.matches.get(0).unwrap().ip.clone();
                let tmp_file = format!("./data/{}.json", ip_address);
                let mut file = File::create(tmp_file).unwrap();
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
    let mut files = std::fs::File::open("/tmp/test.lua").unwrap();
    let mut contents = String::new();
    let _ = files.read_to_string(&mut contents).unwrap();
    let lua = Lua::new();
    let global_s = lua.globals();
    global_s.set("gstr", "hello").unwrap();
    lua.load(&contents).exec().unwrap();
    let lua_version: String = global_s.get("_VERSION").unwrap();
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
    let mut speedtestconfig = speedtest_rs::speedtest::get_configuration().unwrap();
    let server_list_sorted;
    let server_list = speedtest_rs::speedtest::get_server_list_with_config(&speedtestconfig).unwrap();
    server_list_sorted = server_list.servers_sorted_by_distance(&speedtestconfig);
    let latency_test_result = speedtest_rs::speedtest::get_best_server_based_on_latency(&server_list_sorted[..]).unwrap();
    let best_server = latency_test_result.server;
    let inner_upload_measurement =
        speedtest_rs::speedtest::test_upload_with_progress_and_config(best_server, || {
            print!(".");
            io::stdout().flush().unwrap();
        }, &speedtestconfig).expect("Upload speedtest error.");
    let inner_download_measurement = speedtest_rs::speedtest::test_download_with_progress_and_config(best_server, || {
        print!(".");
        io::stdout().flush().unwrap();
    }, &mut speedtestconfig).expect("Download speedtest error.");
    (inner_upload_measurement.bps_f64() as usize, inner_download_measurement.bps_f64() as usize)
}

fn get_root_domain(subdomain: &String) -> String {
    let options = TldOption {
        cache_path: Some(".tld_cache".to_string()),
        private_domains: false,
        update_local: false,
        naive_mode: false,
    };
    let tldex = TldExtractor::new(options);
    let ip_len = ips(subdomain.as_str()).len() + ipv6s(subdomain.as_str()).len();
    let mut sd = String::new();
    if ip_len == 0 {
        let tmp_result = tldex.extract(format!("https://{}", subdomain).as_str()).unwrap();
        let tmp_domain = tmp_result.domain.unwrap();
        let tmp_suffix = tmp_result.suffix.unwrap();
        sd = format!("{}.{}", tmp_domain, tmp_suffix);
    }
    sd
}
