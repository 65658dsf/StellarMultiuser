import pymysql
import hashlib
import base64
from Crypto.Cipher import ARC4
from datetime import datetime
from quart import Quart, request, jsonify

app = Quart(__name__)

# MySQL数据库配置
db_config = {
    "host": "host",
    "port": 3306,
    "user": "username",
    "password": "password",
    "database": "",
}

# RC4加密函数
def rc4_encrypt(data, key1):
    key = bytes(key1, encoding="utf-8")
    enc = ARC4.new(key)
    res = enc.encrypt(data.encode("utf-8"))
    res = base64.b64encode(res)
    return res.decode("utf-8")

# 生成 token
def generate_token(token):
    encrypted = rc4_encrypt(token, "密钥")
    return hashlib.md5(encrypted.encode()).hexdigest()

class OpController:
    def __init__(self):
        self.connection = pymysql.connect(**db_config)

    def register(self, app):
        app.add_url_rule("/free", view_func=self.handle_login, methods=["POST"])
        app.add_url_rule("/check_proxy", view_func=self.check_proxy, methods=["POST"])
        app.add_url_rule("/vip", view_func=self.vip_check, methods=["POST"])  # 新增路由
    def get_user_token(self, user):
        try:
            connection = pymysql.connect(**db_config)
            with connection.cursor() as cursor:
                sql = "SELECT token FROM users WHERE username = %s"
                cursor.execute(sql, (user,))
                result = cursor.fetchone()
                if result:
                    return result[0]
                return None
        except Exception as e:
            print(f"Database error: {e}")
            return None

    async def handle_login(self):
        # 获取请求参数
        version = request.args.get("version")
        op = request.args.get("op")

        # 验证操作类型是否为 Login
        if version != "0.1.0" or op != "Login":
            return jsonify({"reject": True, "reject_reason": "无效的版本或操作"})

        # 解析请求体
        data = await request.get_json()
        if not data or "content" not in data:
            return jsonify({"reject": True, "reject_reason": "请求体缺失"})

        content = data["content"]
        user = content.get("user", "")
        token = content.get("metas", {}).get("token", "")

        # 验证用户和 token
        if not user or not token:
            return jsonify({"reject": True, "reject_reason": "用户名或密码不能为空"})

        # 从数据库获取用户的token
        db_token = self.get_user_token(user)
        if not db_token:
            return jsonify({"reject": True, "reject_reason": "用户不存在"})

        # 使用数据库密码生成 token
        generated_token = generate_token(db_token)

        # 验证 token 是否正确
        if generated_token == token:
            return jsonify({"reject": False, "unchange": True})
        else:
            return jsonify({"reject": True, "reject_reason": "密码无效"})

    async def check_proxy(self):
        data = await request.get_json()
        # 获取请求中的校验字段
        username = data["content"]["user"].get("user")
        proxy_name = data['content']['proxy_name']
        proxy_name = proxy_name.split('.')[1]
        proxy_type = data["content"].get("proxy_type")
        remote_port = data["content"].get("remote_port")
        if not all([username, proxy_name, proxy_type, remote_port]):
            return jsonify({"reject": True, "reject_reason": "缺少必要参数"})
        if self.verify_proxy(username, proxy_name, proxy_type, remote_port):
            return jsonify(
                {"reject": False, "unchange": True, "reject_reason": "隧道校验成功"}
            )
        else:
            return jsonify({"reject": True, "reject_reason": "隧道校验失败"})

    def verify_proxy(self, username, proxy_name, proxy_type, remote_port):
        try:
            # 每次查询时创建新的数据库连接
            connection = pymysql.connect(**db_config)
            with connection.cursor() as cursor:
                sql = """
                SELECT * FROM proxy
                WHERE username = %s
                AND proxy_name = %s
                AND proxy_type = %s
                AND remote_port = %s
                """
                cursor.execute(sql, (username, proxy_name, proxy_type, remote_port))
                result = cursor.fetchone()
                connection.close()  # 查询后关闭连接
                return result is not None
        except Exception as e:
            print(f"Database error: {e}")
            return False


    async def vip_check(self):
        data = await request.get_json()
        user = data["content"].get("user", "")
        if not user:
            return jsonify({"reject": True, "reject_reason": "用户名不能为空"})

        vip_info = self.get_user_vip_info(user)
        if not vip_info:
            return jsonify({"reject": True, "reject_reason": "用户不存在或不是VIP"})

        user_type, vip_time = vip_info
        current_time = datetime.now()
        if user_type == "VIP" and vip_time > current_time:
            return jsonify({"reject": False, "unchange": True, "reject_reason": "VIP 校验成功"})
        else:
            return jsonify({"reject": True, "reject_reason": "用户类型非VIP或VIP已过期"})

    def get_user_vip_info(self, user):
        try:
            # 在每次查询时创建新的连接
            connection = pymysql.connect(**db_config)
            with connection.cursor() as cursor:
                sql = "SELECT type, VIPTime FROM users WHERE username = %s"
                cursor.execute(sql, (user,))
                result = cursor.fetchone()
                connection.close()  # 查询后关闭连接
                if result:
                    return result
                return None
        except Exception as e:
            print(f"Database error: {e}")
            return None

# 创建控制器并注册路由
controller = OpController()
controller.register(app)

if __name__ == "__main__":
    app.run()
