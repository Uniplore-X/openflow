import * as os from "os";
import * as path from "path";
import * as http from "http";
import * as https from "https";
import * as express from "express";
import * as compression from "compression";
import * as cookieParser from "cookie-parser";
import * as nodered from "node-red";
import * as morgan from "morgan";

// import * as samlauth from "./node-red-contrib-auth-saml";

import { nodered_settings } from "./nodered_settings";
import { Config } from "./Config";
import { noderedcontribopenflowstorage, noderednpmrc } from "./node-red-contrib-openflow-storage";
import { noderedcontribmiddlewareauth } from "./node-red-contrib-middleware-auth";

import * as passport from "passport";
import { noderedcontribauthsaml } from "./node-red-contrib-auth-saml";
import { WebSocketClient, NoderedUtil, Message } from "@openiap/openflow-api";
import { Histogram, Counter, Observable, ObservableResult } from "@opentelemetry/api-metrics"
import { HrTime, Span } from "@opentelemetry/api";
import { hrTime, hrTimeToMilliseconds } from "@opentelemetry/core";
import * as RED from "node-red";
import { Red } from "node-red";
import { Logger } from "./Logger";
var _hostname = "";

export class log_message_node {
    public span: Span;
    public end: HrTime;
    public nodetype: string;
    public node: Red;
    public name: string;
    constructor(public nodeid: string) {
        this.node = RED.nodes.getNode(nodeid);
        if (this.node != null) {
            this.nodetype = this.node.type;
            this.name = this.node.name || this.node.type;
        }
    }
    startspan(parentspan: Span, msgid) {
        this.span = Logger.otel.startSubSpan(this.name, parentspan);
        this.span?.setAttributes(Logger.otel.defaultlabels);
        this.span?.setAttribute("msgid", msgid);
        this.span?.setAttribute("nodeid", this.nodeid);
        this.span?.setAttribute("nodetype", this.nodetype)
        this.span?.setAttribute("name", this.name)
        // nodemessage.span = otel.startSpan2(msg.event, msg.msgid);
        this.end = Logger.otel.startTimer();
    }
}
export class log_message {
    public hrtimestamp: HrTime;
    public nodes: { [key: string]: log_message_node; } = {};
    public node: Red;
    public name: string;
    public traceId: string;
    public spanId: string;
    // public nodes: object = {}
    constructor(public msgid: string) {
        this.hrtimestamp = hrTime();
        this.nodes = {};
    }
    public static nodeexpire(msgid: string, nodeid: string) {
        if (WebServer.log_messages[msgid] == undefined) return;
        const logmessage = WebServer.log_messages[msgid];
        if (!logmessage.nodes[nodeid]) return;

        const nodemessage = logmessage.nodes[nodeid];
        if (nodemessage.span) {
            // end time is NOT working, so sadly we need to discard this span :-(
            // nodemessage.span?.end(logmessage.hrtimestamp);
            delete nodemessage.span;
        }
        if (nodemessage.end) {
            // Logger.otel.endTimer(nodemessage.end, WebServer.openflow_nodered_node_duration, { nodetype: nodemessage.nodetype });
            WebServer.openflow_nodered_node_duration.record(1 / 5, { nodetype: nodemessage.nodetype })
            delete nodemessage.end;
        }
        delete logmessage.nodes[nodeid];
    }
    public static nodeend(msgid: string, nodeid: string) {
        if (WebServer.log_messages[msgid] == undefined) return;
        const logmessage = WebServer.log_messages[msgid];
        if (!logmessage.nodes[nodeid]) return;
        logmessage.hrtimestamp = hrTime();

        const nodemessage = logmessage.nodes[nodeid];
        if (nodemessage.span) {
            Logger.otel.endSpan(nodemessage.span, null);
            delete nodemessage.span;
        }
        if (nodemessage.end) {
            Logger.otel.endTimer(nodemessage.end, WebServer.openflow_nodered_node_duration, { nodetype: nodemessage.nodetype });
            delete nodemessage.end;
        }
        delete logmessage.nodes[nodeid];
    }
    public static nodestart(msgid: string, nodeid: string): log_message_node {
        if (WebServer.log_messages[msgid] == undefined) WebServer.log_messages[msgid] = new log_message(msgid);
        const logmessage = WebServer.log_messages[msgid];
        if (!logmessage.nodes[msgid]) logmessage.nodes[nodeid] = new log_message_node(nodeid);
        // Update last activity 
        logmessage.hrtimestamp = hrTime();

        const nodemessage = logmessage.nodes[nodeid];
        nodemessage.end = Logger.otel.startTimer();

        nodemessage.span = Logger.otel.startSpan(nodemessage.name, logmessage.traceId, logmessage.spanId);
        nodemessage.span?.setAttributes(Logger.otel.defaultlabels);
        nodemessage.span?.setAttribute("msgid", msgid);
        nodemessage.span?.setAttribute("nodeid", nodeid);
        nodemessage.span?.setAttribute("nodetype", nodemessage.nodetype)
        nodemessage.span?.setAttribute("name", nodemessage.name)
        const [traceId, spanId] = Logger.otel.GetTraceSpanId(nodemessage.span);
        //if (NoderedUtil.IsNullEmpty(logmessage.traceId)) {
        logmessage.traceId = traceId;
        logmessage.spanId = spanId;
        //}
        return nodemessage;
    }
}
export class WebServer {
    private static app: express.Express = null;

    public static openflow_nodered_node_duration: Histogram;
    public static message_queue_count: Observable;
    public static log_messages: { [key: string]: log_message; } = {};
    private static settings: nodered_settings = null;
    static async configure(socket: WebSocketClient): Promise<http.Server> {
        const options: any = null;
        const RED: nodered.Red = nodered;

        if (this.app !== null) { return; }

        if (!NoderedUtil.IsNullUndefinded(Logger.otel)) {
            this.openflow_nodered_node_duration = Logger.otel.meter.createHistogram('openflow_nodered_node_duration', {
                description: 'Duration of each node type call'
            });
            this.message_queue_count = Logger.otel.meter.createObservableUpDownCounter("openflow_message_queue_count", {
                description: 'Total number messages waiting on reply from client'
            })
            if (this.message_queue_count) this.message_queue_count.addCallback(this.update_message_queue_count.bind(this));
        }
        try {
            Logger.instanse.silly("WebServer", "configure", "begin");
            let server: http.Server = null;
            if (this.app === null) {
                this.app = express();
                this.app.disable("x-powered-by");


                const hostname = Config.getEnv("HOSTNAME", null);
                const defaultLabels: any = {};
                if (!NoderedUtil.IsNullEmpty(hostname)) defaultLabels["hostname"] = hostname;
                const name = Config.getEnv("nodered_id", null);
                if (!NoderedUtil.IsNullEmpty(name)) defaultLabels["name"] = name;
                if (NoderedUtil.IsNullEmpty(name)) defaultLabels["name"] = hostname;
                Logger.instanse.silly("WebServer", "configure", "configure register");
                const loggerstream = {
                    write: function (message, encoding) {
                        Logger.instanse.silly("WebServer", "configure", message);
                    }
                };
                Logger.instanse.silly("WebServer", "configure", "setup express middleware");
                this.app.use(morgan('combined', { stream: loggerstream }));
                this.app.use(compression());
                this.app.use(express.urlencoded({ limit: '10mb', extended: true }))
                this.app.use(express.json({ limit: '10mb' }))
                this.app.use(cookieParser());
                this.app.use("/", express.static(path.join(__dirname, "/public")));

                var session = require('express-session')
                this.app.use(session({ secret: Config.cookie_secret, cookie: { maxAge: 60000 } }))

                this.app.use(passport.initialize());
                this.app.use(passport.session());
                passport.serializeUser(async function (user: any, done: any): Promise<void> {
                    done(null, user);
                });
                passport.deserializeUser(function (user: any, done: any): void {
                    done(null, user);
                });
                if (Config.tls_crt != '' && Config.tls_key != '') {
                    Logger.instanse.silly("WebServer", "configure", "configure ssl");
                    let options: any = {
                        cert: Config.tls_crt,
                        key: Config.tls_key
                    };
                    if (Config.tls_crt.indexOf("---") == -1) {
                        options = {
                            cert: Buffer.from(Config.tls_crt, 'base64').toString('ascii'),
                            key: Buffer.from(Config.tls_key, 'base64').toString('ascii')
                        };
                    }
                    let ca: string = Config.tls_ca;
                    if (ca !== "") {
                        if (ca.indexOf("---") === -1) {
                            ca = Buffer.from(ca, 'base64').toString('ascii');
                        }
                        if (ca.indexOf("---") > -1) {
                            options.ca = ca;
                        }
                        // options.cert += "\n" + ca;
                    }
                    if (Config.tls_passphrase !== "") {
                        options.passphrase = Config.tls_passphrase;
                    }
                    Logger.instanse.silly("WebServer", "configure", "create https server");
                    server = https.createServer(options, this.app);

                    const redirapp = express();
                    redirapp.disable("x-powered-by");
                    // const _http = http.createServer(redirapp);
                    redirapp.get('*', function (req, res) {
                        // res.redirect('https://' + req.headers.host + req.url);
                        res.status(200).json({ status: "ok" });
                    })
                    // _http.listen(80);
                } else {
                    Logger.instanse.silly("WebServer", "configure", "create http server");
                    server = http.createServer(this.app);
                }
                server.on("error", (error) => {
                    Logger.instanse.error("WebServer", "onerror", error);
                });

                Logger.instanse.silly("WebServer", "configure", "configure nodered settings");
                this.settings = new nodered_settings();
                this.settings.functionExternalModules = Config.function_external_modules;
                this.settings.editorTheme.codeEditor.lib = Config.codeeditor_lib;
                if (Config.nodered_port > 0) {
                    this.settings.uiPort = Config.nodered_port;
                }
                else {
                    this.settings.uiPort = Config.port;
                }
                this.settings.functionGlobalContext.NoderedUtil = NoderedUtil;
                setInterval(() => {
                    const keys = Object.keys(WebServer.log_messages);
                    keys.forEach(key => {
                        const msg = WebServer.log_messages[key];

                        const performanceTimeOriginms = hrTimeToMilliseconds(msg.hrtimestamp);
                        const Milliseconds = (hrTimeToMilliseconds(hrTime()) - performanceTimeOriginms)
                        const Seconds = Milliseconds / 1000;
                        if (Seconds > Config.otel_trace_max_node_time_seconds) {
                            const keys = Object.keys(msg.nodes);
                            for (let i = 0; i < keys.length; i++) {
                                const nodemessage = msg.nodes[keys[i]];
                                log_message.nodeexpire(msg.msgid, nodemessage.nodeid);
                            }
                            delete WebServer.log_messages[key];
                        }
                    });
                }, 1000)
                this.settings.logging.customLogger = {
                    level: 'debug',
                    metrics: true,
                    handler: function (settings) {
                        return function (msg) {
                            try {
                                if (!NoderedUtil.IsNullEmpty(msg.msgid) && msg.event.startsWith("node.")) {
                                    msg.event = msg.event.substring(5);
                                    if (msg.event.endsWith(".receive")) {
                                        log_message.nodestart(msg.msgid, msg.nodeid);
                                    }
                                    if (msg.event.endsWith(".send")) {
                                        msg.event = msg.event.substring(0, msg.event.length - 5);
                                        log_message.nodeend(msg.msgid, msg.nodeid);
                                        log_message.nodestart(msg.msgid, msg.nodeid);
                                    }
                                    if (msg.event.endsWith(".done")) {
                                        log_message.nodeend(msg.msgid, msg.nodeid);
                                    }
                                }
                            } catch (error) {
                                console.trace(error);
                                console.error(error);
                                Logger.instanse.silly("WebServer", "configure", error);
                            }

                        }
                    }
                }



                this.settings.userDir = path.join(Config.logpath, '.nodered-' + Config.nodered_id)
                this.settings.nodesDir = path.join(__dirname, "./nodered");

                const baseurl = (!NoderedUtil.IsNullEmpty(Config.saml_baseurl) ? Config.saml_baseurl : Config.baseurl());
                this.settings.adminAuth = await noderedcontribauthsaml.configure(baseurl, Config.saml_federation_metadata, Config.saml_issuer,
                    (profile: string | any, done: any) => {
                        const roles: string[] = profile["http://schemas.xmlsoap.org/claims/Group"];
                        if (roles !== undefined) {
                            if (Config.noderedusers !== "") {
                                if (roles.indexOf(Config.noderedusers) !== -1) { profile.permissions = "read"; }
                            }
                            if (Config.noderedadmins !== "") {
                                if (roles.indexOf(Config.noderedadmins) !== -1) { profile.permissions = "*"; }
                            }
                        }
                        // profile.permissions = "*";
                        done(profile);
                    }, "", Config.saml_entrypoint, null);
                this.settings.httpNodeMiddleware = (req: express.Request, res: express.Response, next: express.NextFunction) => {
                    noderedcontribmiddlewareauth.process(socket, req, res, next);
                };
                this.settings.adminAuth.strategy.autoLogin = true

                Logger.instanse.silly("WebServer", "configure", "configure nodered storageModule");
                this.settings.storageModule = new noderedcontribopenflowstorage(socket);
                const n: noderednpmrc = await this.settings.storageModule._getnpmrc();
                if (!NoderedUtil.IsNullUndefinded(n) && !NoderedUtil.IsNullUndefinded(n.catalogues)) {
                    this.settings.editorTheme.palette.catalogues = n.catalogues;
                } else {
                    this.settings.editorTheme.palette.catalogues = ['https://catalogue.nodered.org/catalogue.json'];
                }
                if (!NoderedUtil.IsNullEmpty(Config.noderedcatalogues)) {
                    if (Config.noderedcatalogues.indexOf(";") > -1) {
                        this.settings.editorTheme.palette.catalogues = Config.noderedcatalogues.split(";");
                    } else {
                        this.settings.editorTheme.palette.catalogues = Config.noderedcatalogues.split(",");
                    }
                    Logger.instanse.debug("WebServer", "configure", "Force nodered catalogues to be " + Config.noderedcatalogues);
                } else {
                    Logger.instanse.debug("WebServer", "configure", "Using default nodered catalogues as " + this.settings.editorTheme.palette.catalogues);
                }
                this.settings.editorTheme.tours = Config.tours;

                this.settings.ui.path = "ui";
                this.settings.ui.middleware = (req: express.Request, res: express.Response, next: express.NextFunction) => {
                    noderedcontribmiddlewareauth.process(socket, req, res, next);
                };

                this.app.set('trust proxy', 1)

                Logger.instanse.debug("WebServer", "configure", "WebServer.configure::init nodered");
                // initialise the runtime with a server and settings
                await (RED as any).init(server, this.settings);

                // serve the editor UI from /red
                this.app.use(this.settings.httpAdminRoot, RED.httpAdmin);

                // serve the http nodes UI from /api
                this.app.use(this.settings.httpNodeRoot, RED.httpNode);

                this.app.get("/livenessprobe", (req: any, res: any, next: any): void => {
                    if (NoderedUtil.IsNullEmpty(_hostname)) _hostname = (Config.getEnv("HOSTNAME", undefined) || os.hostname()) || "unknown";
                    res.end(JSON.stringify({ "success": "true", "hostname": _hostname }));
                    res.end();
                });

                if (Config.nodered_port > 0) {
                    Logger.instanse.debug("WebServer", "configure", "server.listen on port " + Config.nodered_port);
                    server.listen(Config.nodered_port).on('error', function (error) {
                        Logger.instanse.error("WebServer", "configure", error);
                        if (Config.NODE_ENV == "production") {
                            try {
                                server.close();
                            } catch (error) {
                            }
                            process.exit(404);
                        }
                    });
                }
                else {
                    Logger.instanse.debug("WebServer", "configure", "server.listen on port " + Config.port);
                    server.listen(Config.port).on('error', function (error) {
                        Logger.instanse.error("WebServer", "configure", error);
                        if (Config.NODE_ENV == "production") {
                            try {
                                server.close();
                            } catch (error) {
                            }
                            process.exit(404);
                        }
                    });
                }

            } else {
                await RED.stop();
                // initialise the runtime with a server and settings
                await (RED as any).init(server, this.settings);

                // serve the editor UI from /red
                this.app.use(this.settings.httpAdminRoot, RED.httpAdmin);

                // serve the http nodes UI from /api
                this.app.use(this.settings.httpNodeRoot, RED.httpNode);
            }

            let hasErrors: boolean = true, errorCounter: number = 0, err: any;
            while (hasErrors) {
                try {
                    if (errorCounter > 0) Logger.instanse.warn("WebServer", "configure", "restarting nodered ...");
                    RED.start();
                    hasErrors = false;
                } catch (error) {
                    err = error;
                    errorCounter++;
                    hasErrors = true;
                    Logger.instanse.error("WebServer", "configure", error);
                }
                if (errorCounter == 10) {
                    throw err;
                } else if (hasErrors) {
                    const wait = ms => new Promise((r, j) => setTimeout(r, ms));
                    await wait(2000);
                }
            }
            return server;
        } catch (error) {
            Logger.instanse.error("WebServer", "configure", error);
            if (Config.NODE_ENV == "production") {
                process.exit(404);
            }
        }
        return null;
    }
    public static update_message_queue_count(res: ObservableResult) {
        if (!Config.otel_measure_queued_messages) return;
        if (!WebServer.message_queue_count) return;
        if (NoderedUtil.IsNullUndefinded(res) || NoderedUtil.IsNullUndefinded(res.observe)) return;
        var cli: WebSocketClient = WebSocketClient.instance;
        const result: any = {};
        const keys = Object.keys(cli.messageQueue);
        keys.forEach(key => {
            try {
                const qmsg = cli.messageQueue[key];
                var o = qmsg.message;
                if (typeof o === "string") o = JSON.parse(o);
                const msg: Message = o;
                if (result[msg.command] == null) result[msg.command] = 0;
                result[msg.command]++;
            } catch (error) {
                Logger.instanse.error("WebServer", "configure", error);
            }
        });
        const keys2 = Object.keys(result);
        keys2.forEach(key => {
            res.observe(result[key], { ...Logger.otel.defaultlabels, command: key });
        });
    }
}