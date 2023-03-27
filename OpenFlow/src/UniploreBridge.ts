import * as express from "express";
import { Span } from "@opentelemetry/api";
import { Config } from "./Config";
import { Crypt } from "./Crypt";
import { Audit } from "./Audit";
import { Logger } from "./Logger";
import { LoginProvider, Provider } from "./LoginProvider"
import { Base, User, NoderedUtil, TokenUser, Role, Rolemember } from "@openiap/openflow-api";

export class UniploreBridge{
    private app: express.Express;
    public static instance: UniploreBridge = null;

    constructor(app: express.Express){
        this.app=app;
        this.initialize();
    }

    static configure(app: express.Express): UniploreBridge{
        const bridge: UniploreBridge = new UniploreBridge(app);
        UniploreBridge.instance=bridge;

        return bridge;
    }

    initialize(): void{
        //!!!!!!!!!!!注意：只能在内网安全环境中访问此接口！！！！！
        this.app.post("/uniploreBridge",async(req,res)=>{
            const action: string=req.query.action as string || "";
            const span: Span = Logger.otel.startSpanExpress("UniploreBridge."+action, req);

            try {
                Logger.instanse.debug("Adding new local strategy", span);

                span?.setAttribute("remoteip", LoginProvider.remoteip(req));

                try{
                    switch(action){
                        case "ensureAdmin":
                            await this.ensureAdmin(req, res, span);
                            break;
                        default: //unknown
                        this.response(res, {code: 404, msg: "unknown action: " + action});
                            break;
                    }
                }catch(e){
                    this.response(res, {code: 1000, msg: typeof e=="string" ? e : e.toString()});
                    throw e;
                }
                

                Logger.otel.endSpan(span);
            } catch (error) {
                Logger.instanse.error(error, span);
                Logger.otel.endSpan(span);
            }
            

            span.end();
        });

        this.app.get("/uniplore-test",(req,res)=>{
            res.send("Hello World!");
        });
    }

    //参考：LoginProvider.CreateLocalStrategy
    private async ensureAdmin(req, res, span: Span) {
        //注意name、username不能是openflow保留的名称：如root,admin,administrator等

        const params=req.body;
        const isUniploreAdmin = !!params.isUniploreAdmin as boolean;
        const devPassword: string = params.devPassword;
        let name: string = params.name || params.username;
        let username: string = params.username;

        let password: string = null;//无需密码，内部会生成随机密码
        if (username !== null && username != undefined) { username = username.toLowerCase(); }

        let remoteip: string = "";
        if (!NoderedUtil.IsNullUndefinded(req)) {
            remoteip = LoginProvider.remoteip(req);
        }


        let user: User = await Logger.DBHelper.FindByUsername(username, null, span);
        const providers = await Logger.DBHelper.GetProviders(span);

        if (providers.length === 0 || NoderedUtil.IsNullEmpty(providers[0]._id)) {
            if(!isUniploreAdmin){
                this.response(res, { code: 1000, msg: "进行OpenFlow初始化时，必须使用uniplore管理员帐号" });
                return;
            }

            //user = await Logger.DBHelper.FindByUsername(username, null, span);
            if (user == null) {//【系统初始化】的首个用户为管理员
                Logger.instanse.info("No login providers, creating " + username + " as admin", span);
                user = new User(); user.name = name; user.username = username;
                //await Crypt.SetPassword(user, password, span);
                const jwt: string = Crypt.rootToken();
                user = await Logger.DBHelper.EnsureUser(jwt, user.name, user.username, null, devPassword ? devPassword : password, null, span);

                const admins: Role = await Logger.DBHelper.FindRoleByName("admins", null, span);
                if (admins == null) throw new Error("Failed locating admins role!")
                admins.AddMember(user);
                await Logger.DBHelper.Save(admins, Crypt.rootToken(), span)
            }else{
                // if (!(await Crypt.ValidatePassword(user, password, span))) {
                //     Logger.instanse.error("No login providers, login for " + username + " failed", span);
                //     await Audit.LoginFailed(username, "weblogin", "local", remoteip, "browser", "unknown", span);
                //     return done(null, false);
                // }

                Logger.instanse.info("No login providers, updating " + username + " as admin", span);
                const admins: Role = await Logger.DBHelper.FindRoleByName("admins", null, span);
                if (admins == null) throw new Error("Failed locating admins role!")
                admins.AddMember(user);
                await Logger.DBHelper.Save(admins, Crypt.rootToken(), span)
            }

            Logger.instanse.info("Clear cache", span);
            await Logger.DBHelper.clearCache("Initialized", span);
            await Audit.LoginSuccess(TokenUser.From(user), "local", "local", remoteip, "browser", "unknown", span);
            const provider: Provider = new Provider(); provider.provider = "local"; provider.name = "Local";
            Logger.instanse.info("Saving local provider", span);
            const result = await Config.db.InsertOne(provider, "config", 0, false, Crypt.rootToken(), span);
            Logger.instanse.info("local provider created as " + result._id, span);
            await Logger.DBHelper.CheckCache("config", result, false, false, span);
        }else if(user==null){//用户不存在，则创建
            const rootJwt: string = Crypt.rootToken();
            user = new User(); user.name = name; user.username = username;
            user = await Logger.DBHelper.EnsureUser(rootJwt, user.name, user.username, null, password, null, span);
        }else if(user.name!==name){
           const rootJwt: string = Crypt.rootToken();
            user.name=name;
            await Logger.DBHelper.Save(user,rootJwt,span);
        }

        //判断是否为管理员，若不是、则设置管理员角色
        const admins: Role = await Logger.DBHelper.FindRoleByName("admins", null, span);
        if (admins == null) throw new Error("Failed locating admins role!")

        if (!admins.IsMember(user._id)) {
            const rootJwt: string = Crypt.rootToken();
            admins.AddMember(user);
            await Logger.DBHelper.Save(admins, rootJwt, span);
        }

        const jwt = Crypt.createToken(user, Config.shorttoken_expires_in);

        await Audit.LoginSuccess(TokenUser.From(user), "local", "local", remoteip, "browser", "unknown", span);

        this.response(res, { code: 200, data: {jwt} });
    }

    private response(res, result){
        res.json(result);
    }


}