import * as https from "https";
import * as fs from "fs";
import * as path from "path";
import { fetch, toPassportConfig } from "passport-saml-metadata";
import { NoderedUtil } from "@openiap/openflow-api";
import { promiseRetry } from "./Logger";
const { networkInterfaces } = require('os');
export class Config {
    public static getversion(): string {
        let versionfile: string = path.join(__dirname, "VERSION");
        if (!fs.existsSync(versionfile)) versionfile = path.join(__dirname, "..", "VERSION")
        if (!fs.existsSync(versionfile)) versionfile = path.join(__dirname, "..", "..", "VERSION")
        if (!fs.existsSync(versionfile)) versionfile = path.join(__dirname, "..", "..", "..", "VERSION")
        Config.version = (fs.existsSync(versionfile) ? fs.readFileSync(versionfile, "utf8") : "0.0.1");
        return Config.version;
    }
    public static reload(): void {
        Config.getversion();
        Config.logpath = Config.getEnv("logpath", __dirname);
        Config.enable_file_cache = Config.parseBoolean(Config.getEnv("log_with_colors", "true"));
        Config.log_with_colors = Config.parseBoolean(Config.getEnv("log_with_colors", "true"));
        Config.log_with_trace = Config.parseBoolean(Config.getEnv("log_with_trace", "false"));

        Config.log_information = Config.parseBoolean(Config.getEnv("log_information", "true"));
        Config.log_debug = Config.parseBoolean(Config.getEnv("log_debug", "false"));
        Config.log_verbose = Config.parseBoolean(Config.getEnv("log_verbose", "false"));
        Config.log_silly = Config.parseBoolean(Config.getEnv("log_silly", "false"));
        Config.log_otel = Config.parseBoolean(Config.getEnv("log_otel", "false"));
        Config.log_webserver = Config.parseBoolean(Config.getEnv("log_webserver", "false"));
        Config.log_storage = Config.parseBoolean(Config.getEnv("log_storage", "false"));

        Config.nodered_id = Config.getEnv("nodered_id", "1");
        Config.nodered_sa = Config.getEnv("nodered_sa", "");

        Config.NODE_ENV = Config.getEnv("NODE_ENV", "development");
        Config.HTTP_PROXY = Config.getEnv("HTTP_PROXY", "");
        Config.HTTPS_PROXY = Config.getEnv("HTTPS_PROXY", "");
        Config.NO_PROXY = Config.getEnv("NO_PROXY", "");

        Config.saml_federation_metadata = Config.getEnv("saml_federation_metadata", "");
        Config.saml_issuer = Config.getEnv("saml_issuer", "");
        Config.saml_entrypoint = Config.getEnv("saml_entrypoint", "");
        Config.saml_baseurl = Config.getEnv("saml_baseurl", "");
        Config.saml_crt = Config.getEnv("saml_crt", "");
        Config.saml_ignore_cert = Config.parseBoolean(Config.getEnv("saml_ignore_cert", "false"));

        Config.port = parseInt(Config.getEnv("port", "1880"));
        Config.nodered_port = parseInt(Config.getEnv("nodered_port", "0"));
        Config.domain = Config.getEnv("domain", "localhost");
        Config.domain_use_ip_from_network = Config.getEnv("domain_use_ip_from_network", ""); // grab ip address from this adaptor and use for domain
        Config.protocol = Config.getEnv("protocol", "http");
        Config.noderedusers = Config.getEnv("noderedusers", "");
        Config.noderedadmins = Config.getEnv("noderedadmins", "");
        Config.noderedapiusers = Config.getEnv("noderedapiusers", "");
        Config.noderedcatalogues = Config.getEnv("noderedcatalogues", "");
        Config.cookie_secret = Config.getEnv("cookie_secret", "NLgUIsozJaxO38ze0WuHthfj2eb1eIEu");

        Config.flow_refresh_interval = parseInt(Config.getEnv("flow_refresh_interval", "60000"));
        Config.flow_refresh_initial_interval = parseInt(Config.getEnv("flow_refresh_initial_interval", "60000"));
        Config.workflow_node_auto_cleanup = Config.parseBoolean(Config.getEnv("workflow_node_auto_cleanup", "true"));

        Config.api_ws_url = Config.getEnv("api_ws_url", "ws://localhost:3000");
        Config.amqp_url = Config.getEnv("amqp_url", "amqp://localhost");
        Config.amqp_reply_expiration = parseInt(Config.getEnv("amqp_reply_expiration", (60 * 1000).toString())); // 1 min
        Config.amqp_workflow_out_expiration = parseInt(Config.getEnv("amqp_workflow_out_expiration", (60 * 1000).toString())); // 1 min
        Config.amqp_reply_expiration = parseInt(Config.getEnv("amqp_reply_expiration", "10000")); // 10 seconds
        Config.amqp_enabled_exchange = Config.parseBoolean(Config.getEnv("amqp_enabled_exchange", "false"));


        Config.api_credential_cache_seconds = parseInt(Config.getEnv("api_credential_cache_seconds", "300"));
        Config.api_allow_anonymous = Config.parseBoolean(Config.getEnv("api_allow_anonymous", "false"));
        Config.function_external_modules = Config.parseBoolean(Config.getEnv("function_external_modules", "false"));
        Config.codeeditor_lib = Config.getEnv("codeeditor_lib", "");

        Config.jwt = Config.getEnv("jwt", "");

        Config.aes_secret = Config.getEnv("aes_secret", "");
        Config.tls_crt = Config.getEnv("tls_crt", "");
        Config.tls_key = Config.getEnv("tls_key", "");
        Config.tls_ca = Config.getEnv("tls_ca", "");
        Config.tls_passphrase = Config.getEnv("tls_passphrase", "");

        Config.amqp_message_ttl = parseInt(Config.getEnv("amqp_message_ttl", "20000"));
        Config.otel_trace_max_node_time_seconds = parseInt(Config.getEnv("otel_trace_max_node_time_seconds", "300"));
        Config.otel_measure_nodeid = Config.parseBoolean(Config.getEnv("otel_measure_nodeid", "false"));
        Config.otel_measure_queued_messages = Config.parseBoolean(Config.getEnv("otel_measure_queued_messages", "false"));
        Config.max_message_queue_time_seconds = parseInt(Config.getEnv("max_message_queue_time_seconds", "3600"));
        Config.enable_analytics = Config.parseBoolean(Config.getEnv("enable_analytics", "true"));
        Config.openflow_uniqueid = Config.getEnv("openflow_uniqueid", "");
        Config.otel_debug_log = Config.parseBoolean(Config.getEnv("otel_debug_log", "false"));
        Config.otel_warn_log = Config.parseBoolean(Config.getEnv("otel_warn_log", "false"));
        Config.otel_err_log = Config.parseBoolean(Config.getEnv("otel_err_log", "false"));

        Config.otel_trace_url = Config.getEnv("otel_trace_url", "");
        Config.otel_metric_url = Config.getEnv("otel_metric_url", "");
        Config.otel_trace_interval = parseInt(Config.getEnv("otel_trace_interval", "5000"));
        Config.otel_metric_interval = parseInt(Config.getEnv("otel_metric_interval", "5000"));
    }
    public static version: string = Config.getversion();
    public static unittesting: boolean = false;
    public static logpath: string = Config.getEnv("logpath", __dirname);
    public static enable_file_cache: boolean = Config.parseBoolean(Config.getEnv("log_with_colors", "true"));
    public static log_with_trace: boolean = Config.parseBoolean(Config.getEnv("log_with_trace", "false"));
    public static log_with_colors: boolean = Config.parseBoolean(Config.getEnv("log_with_colors", "true"));
    public static log_information: boolean = Config.parseBoolean(Config.getEnv("log_information", "true"));
    public static log_debug: boolean = Config.parseBoolean(Config.getEnv("log_debug", "false"));
    public static log_verbose: boolean = Config.parseBoolean(Config.getEnv("log_verbose", "false"));
    public static log_silly: boolean = Config.parseBoolean(Config.getEnv("log_silly", "false"));
    public static log_otel: boolean = Config.parseBoolean(Config.getEnv("log_otel", "false"));
    public static log_webserver: boolean = Config.parseBoolean(Config.getEnv("log_webserver", "false"));
    public static log_storage: boolean = Config.parseBoolean(Config.getEnv("log_storage", "false"));

    public static nodered_id: string = Config.getEnv("nodered_id", "1");
    public static nodered_sa: string = Config.getEnv("nodered_sa", "");

    public static NODE_ENV: string = Config.getEnv("NODE_ENV", "development");
    public static HTTP_PROXY: string = Config.getEnv("HTTP_PROXY", "");
    public static HTTPS_PROXY: string = Config.getEnv("HTTPS_PROXY", "");
    public static NO_PROXY: string = Config.getEnv("NO_PROXY", "");

    public static allow_start_from_cache: boolean = Config.parseBoolean(Config.getEnv("allow_start_from_cache", "false"));
    public static auto_restart_when_needed: boolean = Config.parseBoolean(Config.getEnv("auto_restart_when_needed", "true"));


    public static saml_federation_metadata: string = Config.getEnv("saml_federation_metadata", "");
    public static saml_issuer: string = Config.getEnv("saml_issuer", "");
    public static saml_entrypoint: string = Config.getEnv("saml_entrypoint", "");
    public static saml_baseurl: string = Config.getEnv("saml_baseurl", "");
    public static saml_crt: string = Config.getEnv("saml_crt", "");
    public static saml_ignore_cert: boolean = Config.parseBoolean(Config.getEnv("saml_ignore_cert", "false"));

    public static port: number = parseInt(Config.getEnv("port", "1880"));
    public static nodered_port: number = parseInt(Config.getEnv("nodered_port", "0"));
    public static domain: string = Config.getEnv("domain", "localhost");
    public static domain_use_ip_from_network: string = Config.getEnv("domain_use_ip_from_network", ""); // grab ip address from this adaptor and use for domain
    public static protocol: string = Config.getEnv("protocol", "http");
    public static noderedusers: string = Config.getEnv("noderedusers", "");
    public static noderedadmins: string = Config.getEnv("noderedadmins", "");
    public static noderedapiusers: string = Config.getEnv("noderedapiusers", "");
    public static noderedcatalogues: string = Config.getEnv("noderedcatalogues", "");
    public static cookie_secret: string = Config.getEnv("cookie_secret", "NLgUIsozJaxO38ze0WuHthfj2eb1eIEu"); // Used to protect cookies

    public static flow_refresh_interval: number = parseInt(Config.getEnv("flow_refresh_interval", "60000"));
    public static flow_refresh_initial_interval: number = parseInt(Config.getEnv("flow_refresh_initial_interval", "60000"));
    public static workflow_node_auto_cleanup: boolean = Config.parseBoolean(Config.getEnv("workflow_node_auto_cleanup", "true"));

    public static api_ws_url: string = Config.getEnv("api_ws_url", "ws://localhost:3000");
    public static amqp_url: string = Config.getEnv("amqp_url", "amqp://localhost");
    // public static amqp_reply_expiration: number = parseInt(Config.getEnv("amqp_reply_expiration", (60 * 1000).toString())); // 1 min
    // public static amqp_workflow_out_expiration: number = parseInt(Config.getEnv("amqp_workflow_out_expiration", (60 * 1000).toString())); // 1 min
    public static amqp_reply_expiration: number = parseInt(Config.getEnv("amqp_reply_expiration", "10000")); // 10 seconds
    public static amqp_workflow_out_expiration: number = parseInt(Config.getEnv("amqp_workflow_out_expiration", "10000")); // 10 seconds
    public static amqp_enabled_exchange: boolean = Config.parseBoolean(Config.getEnv("amqp_enabled_exchange", "false"));

    public static api_credential_cache_seconds: number = parseInt(Config.getEnv("api_credential_cache_seconds", "300"));
    public static api_allow_anonymous: boolean = Config.parseBoolean(Config.getEnv("api_allow_anonymous", "false"));
    public static function_external_modules: boolean = Config.parseBoolean(Config.getEnv("function_external_modules", "false"));
    public static codeeditor_lib: string = Config.getEnv("codeeditor_lib", "");

    public static jwt: string = Config.getEnv("jwt", "");

    public static aes_secret: string = Config.getEnv("aes_secret", "");
    public static tls_crt: string = Config.getEnv("tls_crt", "");
    public static tls_key: string = Config.getEnv("tls_key", "");
    public static tls_ca: string = Config.getEnv("tls_ca", "");
    public static tls_passphrase: string = Config.getEnv("tls_passphrase", "");

    // Environment variables to set a prefix for RabbitMQs Dead Letter Exchange, Dead Letter Routing Key,
    // Dead Letter Queue, and Message Time to Live - to enable timeouts for RabbitMQ messages
    // These values must be the same for OpenFlowNodeRED and OpenFlow, or will cause errors when asserting queues
    // public static amqp_dlx_prefix: string = Config.getEnv("amqp_dlx_prefix", "DLX.");
    // public static amqp_dlrk_prefix: string = Config.getEnv("amqp_dlrk_prefix", "dlx.");
    // public static amqp_dlq_prefix: string = Config.getEnv("amqp_dlq_prefix", "dlq.");
    public static amqp_message_ttl: number = parseInt(Config.getEnv("amqp_message_ttl", "20000"));
    public static otel_trace_max_node_time_seconds: number = parseInt(Config.getEnv("otel_trace_max_node_time_seconds", "300"));

    public static otel_measure_nodeid: boolean = Config.parseBoolean(Config.getEnv("otel_measure_nodeid", "false"));
    public static otel_measure_queued_messages: boolean = Config.parseBoolean(Config.getEnv("otel_measure_queued_messages", "false"));
    public static max_message_queue_time_seconds: number = parseInt(Config.getEnv("max_message_queue_time_seconds", "3600"));
    public static enable_analytics: boolean = Config.parseBoolean(Config.getEnv("enable_analytics", "true"));
    public static openflow_uniqueid: string = Config.getEnv("openflow_uniqueid", "");
    public static otel_debug_log: boolean = Config.parseBoolean(Config.getEnv("otel_debug_log", "false"));
    public static otel_warn_log: boolean = Config.parseBoolean(Config.getEnv("otel_warn_log", "false"));
    public static otel_err_log: boolean = Config.parseBoolean(Config.getEnv("otel_err_log", "false"));
    public static otel_trace_url: string = Config.getEnv("otel_trace_url", "");
    public static otel_metric_url: string = Config.getEnv("otel_metric_url", "");
    public static otel_trace_interval: number = parseInt(Config.getEnv("otel_trace_interval", "5000"));
    public static otel_metric_interval: number = parseInt(Config.getEnv("otel_metric_interval", "5000"));

    public static tours: boolean = Config.parseBoolean(Config.getEnv("tours", "true"));

    public static baseurl(): string {
        if (!NoderedUtil.IsNullEmpty(Config.domain_use_ip_from_network)) {
            Config.domain_use_ip_from_network = Config.domain_use_ip_from_network.toLowerCase();
            const nets = networkInterfaces();
            for (const name of Object.keys(nets)) {
                for (const net of nets[name]) {
                    // skip over non-ipv4 and internal (i.e. 127.0.0.1) addresses
                    if (net.family === 'IPv4' && !net.internal) {
                        if (name.toLowerCase() == Config.domain_use_ip_from_network) {
                            Config.domain = net.address;
                        }
                    }
                }
            }
        }
        if (NoderedUtil.IsNullEmpty(Config.domain)) {
            if (Config.nodered_sa === null || Config.nodered_sa === undefined || Config.nodered_sa === "") {
                const matches = Config.nodered_id.match(/\d+/);
                if (matches !== null && matches !== undefined) {
                    if (matches.length > 0) {
                        Config.nodered_id = matches[matches.length - 1]; // Just grab the last number
                    }
                }
            }
        }
        // if (Config.tls_crt != '' && Config.tls_key != '') {
        //     return "https://" + Config.domain + ":" + Config.port + "/";
        // }
        // return "http://" + Config.domain + ":" + Config.port + "/";
        let result: string = "";
        if (Config.tls_crt != '' && Config.tls_key != '') {
            result = "https://" + Config.domain;
        } else {
            result = Config.protocol + "://" + Config.domain;
        }
        const port: number = (Config.nodered_port > 0 ? Config.nodered_port : Config.port);
        if (port != 80 && port != 443 && port != 3000) {
            result = result + ":" + port + "/";
        } else { result = result + "/"; }
        return result;
    }

    public static getEnv(name: string, defaultvalue: string): string {
        let value: any = process.env[name];
        if (!value || value === "") { value = defaultvalue; }
        return value;
    }
    public static parseBoolean(s: any): boolean {
        let val: string = "false";
        if (typeof s === "number") {
            val = s.toString();
        } else if (typeof s === "string") {
            val = s.toLowerCase().trim();
        } else if (typeof s === "boolean") {
            val = s.toString();
        } else {
            throw new Error("Unknown type!");
        }
        switch (val) {
            case "true": case "yes": case "1": return true;
            case "false": case "no": case "0": case null: return false;
            default: return Boolean(s);
        }
    }

    public static async parse_federation_metadata(url: string): Promise<any> {
        try {
            if (Config.tls_ca !== "") {
                const tls_ca: string = Buffer.from(Config.tls_ca, 'base64').toString('ascii')
                const rootCas = require('ssl-root-cas/latest').create();
                rootCas.push(tls_ca);
                // rootCas.addFile( tls_ca );
                https.globalAgent.options.ca = rootCas;
                require('https').globalAgent.options.ca = rootCas;
            }
        } catch (error) {
            console.error(error);
        }

        // if anything throws, we retry
        const metadata: any = await promiseRetry(async () => {
            if (Config.saml_ignore_cert) process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
            const reader: any = await fetch({ url });
            if (Config.saml_ignore_cert) process.env.NODE_TLS_REJECT_UNAUTHORIZED = "1";
            if (reader === null || reader === undefined) { throw new Error("Failed getting result"); }
            const config: any = toPassportConfig(reader);
            // we need this, for Office 365 :-/
            if (reader.signingCerts && reader.signingCerts.length > 1) {
                config.cert = reader.signingCerts;
            }
            return config;
        }, 10, 1000);
        return metadata;
    }

}
