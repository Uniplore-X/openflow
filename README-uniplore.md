### 修改说明
#### 在OpenFlow里增加`UniploreBridge.ts`
用于iDIS后端对接

#### 原项目bug修复
- 修复`WebSocketServerClient.ping`消息未发送的问题
- 在`WebSocketServerClient`里收到`ping`消息时，回复一个`pong`消息

### 构建镜像
将openflow与openflow-api放在同一目录，并且没有install过（无需安装依赖），在openflow父目录下执行以下命令：
```shell
docker build -f Dockerfile-uniplore .
```