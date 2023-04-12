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
                        case "ensureUser":
                            await this.ensureUser(req, res, span);
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
    //在iDIS里，首次需要使用初始管理员帐号访问，以完成OpenFlow的初始化
    private async ensureUser(req, res, span: Span) {
        //注意name、username不能是openflow保留的名称：如root,admin,administrator等

        const params=req.body;
        const namePrefix = (params.namePrefix || "") as string; //当检测name或username为保留名称时，会添加该前缀
        const isUniploreAdmin = !!params.isUniploreAdmin as boolean;
        const devPassword: string = params.devPassword; //用于本地开发时，用于访问OpenFlow前端Web页面

        let name: string = params.name || params.username;
        let username: string = params.username;
        const roles: string[] = params.roles ||[];

        const clientagent = params.clientagent;
        const clientversion = params.clientversion;

        let password: string = null;//无需密码，内部会生成随机密码
        if (username !== null && username != undefined) { username = username.toLowerCase(); }

        if(Config.db.WellknownNamesArray.indexOf(name)>=0){
            name=namePrefix+name;
        }

        if(Config.db.WellknownNamesArray.indexOf(username)>=0){
            username=namePrefix+username;
        }

        let remoteip: string = "";
        if (!NoderedUtil.IsNullUndefinded(req)) {
            remoteip = LoginProvider.remoteip(req);
        }

        const rootJwt: string = Crypt.rootToken();

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
                //const jwt: string = Crypt.rootToken();
                user = await Logger.DBHelper.EnsureUser(rootJwt, user.name, user.username, null, devPassword ? devPassword : password, null, span);

                const admins: Role = await Logger.DBHelper.FindRoleByName("admins", null, span);
                if (admins == null) throw new Error("Failed locating admins role!")
                admins.AddMember(user);
                await Logger.DBHelper.Save(admins, rootJwt, span)
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
                await Logger.DBHelper.Save(admins, rootJwt, span)
            }

            Logger.instanse.info("Clear cache", span);
            await Logger.DBHelper.clearCache("Initialized", span);
            await Audit.LoginSuccess(TokenUser.From(user), "local", "local", remoteip, "browser", "unknown", span);
            const provider: Provider = new Provider(); provider.provider = "local"; provider.name = "Local";
            Logger.instanse.info("Saving local provider", span);
            const result = await Config.db.InsertOne(provider, "config", 0, false, rootJwt, span);
            Logger.instanse.info("local provider created as " + result._id, span);
            await Logger.DBHelper.CheckCache("config", result, false, false, span);
        }else if(user==null){//用户不存在，则创建
            user = new User(); user.name = name; user.username = username;
            user = await Logger.DBHelper.EnsureUser(rootJwt, user.name, user.username, null, password, null, span);
        }else if(user.name!==name || user.impersonating){
            user.name=name;
            user.impersonating='';//设置为空，否则无意开启饰演某个角色、导致数据混乱：使用A帐号登录，但实际更改的数据都是B的
            await Logger.DBHelper.Save(user,rootJwt,span);
        }

        if(isUniploreAdmin){//系统管理员始终添加admins角色
            roles.push("admins");
        }

        ////////////////////////////////
        //角色处理
        ///////////////////////////////
        //1.获取当前用户实际拥有的角色
        const currentRolesResult = await Config.db.query({ query: {
            "$and": [
                {"_type": "role"},
                { "members": { "$elemMatch": { "_id": user._id } } },
            ]
        }, skip: 0, top: 100, collectionname: "users", jwt: rootJwt }, span);

        //2.获取需要移除、新添加的角色
        const needRemoveRoles: string[] = [];
        for(let roleItem of currentRolesResult){
            let index = roles.indexOf(roleItem.name);
            if(index==-1){
                needRemoveRoles.push(roleItem.name);
            }else{
                roles.splice(index,1); //已经存在的、移除，剩下的就是新增的
            }
        }

        //3.移除已取消的角色
        for(let rolename of needRemoveRoles){
            const roleObject: Role = await Logger.DBHelper.FindRoleByName(rolename, null, span);
            roleObject.RemoveMember(user._id);
            await Logger.DBHelper.Save(roleObject, rootJwt, span);
        }

        //4.新增角色处理
        for(let rolename of roles){
            const roleObject: Role = await Logger.DBHelper.FindRoleByName(rolename, null, span);
            //if (roleObject == null) throw new Error(`Failed locating ${rolename} role!`)

            if (!roleObject.IsMember(user._id)) {
                roleObject.AddMember(user);
                await Logger.DBHelper.Save(roleObject, rootJwt, span);
            }
        }

        const jwt = Crypt.createToken(user, Config.shorttoken_expires_in);

        await Audit.LoginSuccess(TokenUser.From(user), "local", "local", remoteip, clientagent, clientversion, span);

        this.response(res, { code: 200, data: {jwt,_id: user._id} });
    }

    private response(res: any, result: any){
        res.json(result);
    }


}