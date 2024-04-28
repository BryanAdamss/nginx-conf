# Nginx配置

- 在线可视化配置
	- https://www.digitalocean.com/community/tools/nginx?global.app.lang=zhCN

## 配置文件结构

```nginx
user nginx; # 指定运行 Nginx 的用户和用户组，通常是指定系统中存在的非特权用户。需要确保该用户对 Nginx 所需的文件和目录有适当的访问权限。

worker_processes auto; # 设置 worker 进程数，可以是数字或 `auto`。通常设置为 CPU 核心数的倍数，以充分利用系统资源。

error_log /var/log/nginx/error.log info; # 设置错误日志路径和级别。错误日志是排查问题的重要工具，级别包括 `debug`、`info`、`notice`、`warn`、`error` 等。

pid /var/run/nginx.pid; # 指定保存 Nginx 主进程 ID 的文件路径。通常保存在 `/var/run/nginx.pid`。

worker_rlimit_nofile 8192; # 设置每个 worker 进程的最大打开文件描述符数，影响系统的最大文件打开数。

daemon on; # 启动 Nginx 作为守护进程，即在后台运行。

# events块用于配置与事件驱动机制相关的参数，控制 Nginx 服务器的并发连接处理
events {
    # 配置参数
    worker_connections 1024; # 设置每个 worker 进程的最大连接数
    use epoll; # 选择事件驱动模型，可以是 `select`、`poll`、`kqueue`、`epoll` 等；`epoll` 在 Linux 环境下通常表现较好
}

# http块用于配置 HTTP 服务器的全局参数，并包含了与 HTTP 请求和响应相关的配置。
http {
    include /etc/nginx/mime.types; # 包含其他配置文件，通常包含 MIME 类型配置等。
    default_type application/octet-stream; # 设置默认 MIME 类型

	# 配置全局的访问日志的格式。可以有多个。在http块中都可以访问到
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';
	# 配置访问日志的路径并使用main这种log_format。这是全局日志，会记录所有server块的访问记录
    access_log /var/log/nginx/access.log main;

    # 可以有多个 `server` 块，用于配置不同的虚拟主机，一个server块代表一个虚拟主机
    server {
        # 服务器配置
        listen 80; # 监听的本机某ip地址和端口号，不带ip则默认当前服务器ip。一个服务器可以通过虚拟网络接口技术或在物理网卡上添加多个ip的形式，实现多个ip访问同一台机器；
        server_name example.com; # 设置虚拟主机的域名。进入的请求会携带Host头，server_name和Host头一致 且 请求访问的ip+port和listen匹配，则代表访问的当前server块；当通过ip+port访问，但请求不带Host或Host同server_name不匹配，则无法进入到当前server块，而是进入到nginx的defaultServer，默认server，可通过在listen后指定deafultServer标识来确定，或没有server_name的server也会当成默认server；
        root /usr/share/nginx/html; # 设置网站根目录，从哪找网站资源。
        index index.html index.htm; # 设置默认首页文件，nginx首页找的文件。

		# 设置当前server的访问日志路径并使用http中定义的main日志格式。
		# 其仅仅记录当前server的访问日志
		access_log /var/log/nginx/access-example.log main; 
		error_log log/example_error.log; # 当前虚拟主机的错误日志
		error_page 404 /404.html; # 配置自定义错误页面。

		# 配置全局的gzip，也可在server中单独配置
	    gzip on; # 启用gzip模块
	    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript; # 需要gzip的类型，一般只压缩文本的类型
	    gzip_comp_level 5; # 设置压缩级别（1-9），级别越高压缩率越高，但耗费更多 CPU。
	    gzip_min_length 256; # 设置最小压缩文件大小，小于该值的文件将不会被压缩。
	    gzip_buffers 16 8k; # 设置缓冲区大小。
	    gzip_proxied any; # 启用或禁用代理服务器上的压缩。
	    gzip_vary on; # 启用或禁用根据 Accept-Encoding 头字段的 Vary 头字段。

		# 可以包含多个 `location` 块，用于配置不同的路径规则，location匹配原理见下面的章节
		location / {
			# 处理所有未匹配到其他 location 的请求
			# autoindex on; # 开启自己创建索引目录功能，一般不开启，只在做些简单的静态内容索引时用上
			
			try_files $uri $uri/ /index.html; # 尝试文件路径，用于处理静态文件。

			# 设置CORS，具体设置CORS见下面章节
			add_header 'Access-Control-Allow-Origin' '*';
			add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE';
			add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range';	

			if ($request_method = 'OPTIONS') {
				add_header 'Access-Control-Allow-Origin' '*';
				add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE';
				add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range';
				
				add_header 'Access-Control-Max-Age' 1728000;
				add_header 'Content-Type' 'text/plain; charset=utf-8';
				add_header 'Content-Length' 0;
				return 204;
			}
		}

		location /app/ {
			# 反向代理到后端服务器。反向代理的一些实践见下面章节
		    proxy_pass http://backend_server; # 将以 `/app/` 开头的请求转发给 `http://backend_server`。
		}
		
		location ~ ^/user/(\d+)/ {
			# 重写 URL。
		    rewrite ^/user/(\d+)/$ /profile?id=$1 last; # 将形如 `/user/123/` 的 URL 重写为 `/profile?id=123`。
		}

		location /images/ {
			# 制定别名，用于指定实际文件路径。
			alias /usr/share/nginx/html/images/;  # 将以 `/images/` 开头的请求映射到 `/usr/share/nginx/html/images/` 目录。
			expires 30d; # 设置缓存过期时间。
		}
		
		location /secure/ {
			# 添加响应头。
		    add_header X-Frame-Options "SAMEORIGIN";
		    add_header X-Content-Type-Options "nosniff";
		}

		location = /robots.txt {
			# 直接返回指定的 HTTP 状态码和内容。
		    return 200 "User-agent: *\nDisallow: /";
		}

    }

	server {
		# 其它虚拟主机
		# 开启https，具体开启步骤见下面章节
	    listen 443 ssl; # 启用 HTTPS，并监听 443 端口。
	    server_name your_domain.com;
	
	    ssl_certificate /path/to/your_certificate.crt; # 指定 SSL 证书的路径。
	    ssl_certificate_key /path/to/your_private_key.key; # 指定 SSL 私钥的路径。

		# 其它配置
	}
} 

# 包含其他配置文件，用于模块化配置。可以包含其他配置文件或目录中的所有配置文件。
include /etc/nginx/conf.d/*.conf;
```

## location匹配原理

- 路径匹配原理涉及不同的匹配规则和优先级
- 规则

```nginx
# 前缀匹配（Prefix Match）： `location /path/` 使用前缀匹配，匹配以 `/path/` 开头的请求路径。
location /images/ {
	# 匹配以 /images/ 开头的路径
	# 示例匹配：/images/photo.jpg 
	# 示例不匹配：/documents/file.txt
}

# 精确匹配（Exact Match）： 使用 `=` 前缀可以进行精确匹配，匹配与指定路径完全相同的请求。
location = /path {
	# 精确匹配 /path
	# 示例匹配：/path
	# 示例不匹配：/path/info
}

# 正则表达式匹配： 使用 `~` 或 `~*` 前缀可进行正则表达式匹配，区分大小写或不区分大小写。
location ~ ^/user/\d+/ {
	# 匹配形如 /user/123/ 的路径
	# 示例匹配：/user/456/ 
	# 示例不匹配：/user/john/
}

location ~* \.png$ {
	# 匹配以 .png 结尾的路径，不区分大小写
	# 示例匹配：/images/photo.PNG
	# 示例不匹配：/documents/file.jpg
}

# 最长前缀匹配： 在多个 `location` 中，Nginx 会选择最长的前缀匹配。如果存在两个 `location`，一个是 `/images/`，另一个是 `/images/data/`，请求 `/images/data/file.jpg` 会匹配到 `/images/data/`。
```

- 优先级
	1. **精确匹配优先：** 精确匹配的 `location` 优先级高于前缀匹配。
	2. **正则表达式匹配优先：** 正则表达式匹配的优先级高于前缀匹配。但如果存在精确匹配，精确匹配仍然优先。
	3. **按配置文件中出现的顺序：** 如果存在多个匹配，按照在配置文件中出现的顺序选择第一个匹配。
	4. **总结：**
		- 精确匹配>正则匹配>前缀匹配
		- 同优先级匹配多个location，取第一个匹配
- 注意
	1. **顺序很重要：** `location` 的匹配顺序非常重要，因为第一个匹配成功的 `location` 将会被使用。
	2. **谨慎使用正则表达式：** 正则表达式匹配可能会影响性能，因此谨慎使用。对于简单的路径匹
	3. 配，前缀匹配通常更高效。
	4. **避免冲突：** 当存在多个 `location` 块时，确保它们的路径不会相互冲突，以免出现不符合预期的行为。
	5. **使用 `location /`：** 如果没有精确匹配或更具体的路径匹配，`location /` 可用于处理所有未匹配到其他 `location` 的请求。

```nginx
location / {
    # 处理所有未匹配到其他 location 的请求
}
```

## 反向代理实践

- **基本配置：**
	- `proxy_pass`后跟后端服务器的地址，可以是具体的 IP 地址或域名，也可以是包含协议和端口号的完整地址。

```nginx
location / {
    proxy_pass http://backend_server;
    # 其他代理相关配置...
}
```

- **添加代理头信息：**
	- 使用 `proxy_set_header` 添加额外的头信息，通常用于传递客户端的真实 IP 地址 (`X-Real-IP`)。

```nginx
location / {
    proxy_pass http://backend_server;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    # 其他代理相关配置...
}
```

- **处理后端服务器不同路径：**
	- 如果后端服务器的应用程序部署在路径中，确保 `proxy_pass` 的路径与后端服务器上的路径一致。

```nginx
location /app/ {
    proxy_pass http://backend_server/app/;
    # 其他代理相关配置...
}
```

- **启用代理缓冲：**
	- 启用代理缓冲以减轻后端服务器的负载，可以根据服务器性能调整缓冲的大小。

```nginx
location / {
    proxy_pass http://backend_server;
    proxy_buffering on;
    proxy_buffer_size 4k;
    proxy_buffers 4 4k;
    proxy_busy_buffers_size 8k;
    # 其他代理相关配置...
}
```

- **处理长连接：**
	- 处理长连接，特别是对于 WebSocket 连接，需要设置适当的头信息。

```nginx
location / {
    proxy_pass http://backend_server;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection 'upgrade';
    # 其他代理相关配置...
}
```

- **负载均衡：**
	- 使用 `upstream` 配置实现负载均衡，确保多个后端服务器均衡处理请求。

```nginx
upstream backend_servers {
    server backend1.example.com;
    server backend2.example.com;
    # 其他后端服务器...
}

server {
    location / {
        proxy_pass http://backend_servers;
        # 其他代理相关配置...
    }
}
```

- **错误处理：**
	- 配置适当的错误页面，以提供友好的错误信息给用户。

```nginx
location / {
    proxy_pass http://backend_server;
    error_page 502 503 504 /error.html;
    # 其他代理相关配置...
}
```

- **日志记录：**
	- 启用日志记录以便于故障排除和性能监控。

```nginx
location / {
    proxy_pass http://backend_server;
    access_log /var/log/nginx/proxy_access.log;
    error_log /var/log/nginx/proxy_error.log;
    # 其他代理相关配置...
}
```

## CORS配置

- 配置 CORS（跨域资源共享）是为了让 web 应用程序能够在一个域上使用其他域的资源。

```nginx
server {
    listen 80;
    server_name your_domain.com;

    location / {
		# STEP1：配置基础的CORS头
        add_header 'Access-Control-Allow-Origin' '*'; # 指定允许访问资源的域。`'*'` 表示允许所有域，也可以指定具体的域。
        add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE'; # 指定允许的 HTTP 方法。
        add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range'; # 指定允许的请求头。

		# STEP2：处理OPTIONS请求
		# CORS 通常会发送一个 OPTIONS 预检请求（Preflight Request）来检查是否允许实际的请求
        if ($request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' '*';
            add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE';
            add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range';
            
            add_header 'Access-Control-Max-Age' 1728000;
            add_header 'Content-Type' 'text/plain; charset=utf-8';
            add_header 'Content-Length' 0;
            return 204;
        }
    }
}        
```

## 配置HTTPS

 - HTTPS 相关设置通常是放在 `server` 块内的，因为 HTTPS 设置是针对具体的虚拟主机或站点的。HTTPS 的配置包括 SSL 证书、私钥、协议版本、加密套件等，这些都是与特定的域名或虚拟主机相关的。

1. **获取 SSL 证书：**
	- 你需要获取有效的 SSL 证书。你可以购买 SSL 证书，也可以使用免费的证书颁发机构（CA）如 Let's Encrypt 提供的证书。Let's Encrypt 提供的证书可以通过 Certbot 工具进行免费获取和续订。
2. **安装 SSL 证书：**
	- 将获取到的 SSL 证书文件和私钥文件上传到服务器。通常，证书文件的扩展名为 `.crt` 或 `.pem`，而私钥文件的扩展名为 `.key`。
3. **配置 Nginx 支持 HTTPS：**
	- 打开 Nginx 配置文件，通常位于 `/etc/nginx/nginx.conf` 或 `/etc/nginx/conf.d/default.conf`。确保以下配置项存在或添加：

```nginx
server {
    listen 443 ssl; # 启用 HTTPS，并监听 443 端口。
    server_name your_domain.com;

    ssl_certificate /path/to/your_certificate.crt; # 指定 SSL 证书的路径。
    ssl_certificate_key /path/to/your_private_key.key; # 指定 SSL 私钥的路径。

    # 其他 SSL 配置...
}
```

4. **配置重定向：**
	- 如果你希望所有 HTTP 请求都自动重定向到 HTTPS，可以添加一个额外的 server 配置块：

```nginx
server {
    listen 80;
    server_name your_domain.com;
    
    return 301 https://$host$request_uri; # 将所有 HTTP 请求重定向到 HTTPS。
}
```

5. **配置 SSL 协议和加密套件（可选）：**
	- 可以选择性地配置支持的 SSL 协议版本和加密套件。
	- 根据最新的安全建议，尽量使用更安全的协议版本和加密套件。

```nginx
http {
	# 一些全局的 HTTPS 可以放在 `http` 块内，对所有server生效，也可以server单独配置
	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_ciphers 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384';
}
```

6. **重启验证**

```bash
sudo nginx -t # 验证配置

sudo systemctl reload nginx # 重启

# or

sudo service nginx restart # 重启
```

## URL重写

- 域名迁移时可以使用URL重写保证流量顺利迁移到新域名
- 主要用到`nginx`的`rewrite`功能，`rewrite`可以实现`url`的重写、规范化
- 实用场景
	- 读取`ua`，对爬虫封禁
	- 动态的`url`伪装成静态的`html`页面，便于搜索引擎抓取
	- 新旧域名的更新和迁移
- 语法

```nginx
rewrite regex replacement [flag];
```

- `regex` 是一个正则表达式，用于匹配需要重写的 URL。
    - `replacement` 是一个字符串，用于指定替换的内容。可以使用捕获组来引用正则表达式中的匹配结果。
    - `flag` 是一个可选的标志，用于指定重写规则的行为。常用的标志包括：
        - `last`：表示完成重写操作后停止匹配。
        - `break`：与 `last` 类似，但不会重新尝试匹配其他重写规则。
        - `redirect`：发出临时重定向（HTTP 状态码 302）。
        - `permanent`：发出永久重定向（HTTP 状态码 301）。
        - `if`：条件重写。
- 示例

```nginx
# 将所有请求重写到 index.html
rewrite ^(.*)$ /index.html;

# 重写以 /old 开头的 URL 到以 /new 开头的 URL
rewrite ^/old(.*)$ /new$1;

# 使用正则表达式捕获组进行替换
rewrite ^/blog/(.*)$ /article/$1;

# 发出永久重定向
rewrite ^/oldpage$ /newpage permanent;

```

## 同一台机器绑定多个ip的方法

- 添加虚拟网络接口（Virtual Network Interface）即IP别名（IP aliasing）
	- 这种方式在同一台机器上创建多个网络接口，每一个接口都有自己的IP地址。你可以使用`ifconfig`命令创建额外的接口。比如，下面的命令就创建了一个名为`eth0:1`的虚拟接口，并且给它分配了`192.168.1.2`这个IP地址：

```bash
sudo ifconfig eth0:1 192.168.1.2
```

- 在物理网卡上添加额外的IP地址
	- 对于支持绑定多个ip的网卡，你也可以直接在其上添加多个IP地址。你可以使用`ip`命令添加额外的地址。比如，下面的命令就在`eth0`接口上添加了`192.168.1.2`这个IP地址：

```bash
sudo ip addr add 192.168.1.2 dev eth0
```

- 区别
	- 虚拟网络接口（IP别名）。在这种方式中，虽然物理硬件只有一块，但是在逻辑上我们创建了多个网络接口，每个接口都有各自单独的名字和IP地址。例如，我们可以创建一个名为eth0:1的接口，同时为它分配一个IP地址。这种方式的优点是，它可以清晰地分隔开不同的网络接口和对应的IP地址。
	- 在物理网卡上添加额外的IP地址。这种方式中，我们在同一物理网络接口上绑定了多个IP地址。也就是说，这个网络接口有一个主IP地址，同时还有一个或多个附属IP地址。所有这些地址都属于同一个网络接口，并且可以在这个接口上同时使用。
	- 这两种方式的主要区别在于，虚拟网络接口的方法在逻辑上创建了多个网络接口，每个接口都有自己独立的名字和IP地址，这在一些情况下可能使网络配置更清晰；而在物理网卡上添加额外IP地址的方法则将所有地址都绑定在同一个网络接口上。
