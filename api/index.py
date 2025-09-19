# -*- coding: utf-8 -*-
import os
import json
import base64
import time
from flask import Flask, request, redirect, url_for
from requests_oauthlib import OAuth1Session
from github import Github
import gunicorn
import logging

# 设置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------- 配置环境变量 ----------
CONSUMER_KEY = os.getenv('CONSUMER_KEY')
CONSUMER_SECRET = os.getenv('CONSUMER_SECRET')
CALLBACK_URI = os.getenv('CALLBACK_URI')
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
GITHUB_REPO = os.getenv('GITHUB_REPO', 'qingqiu99/qingqiu99-x-auth-data')
USER_DB_FILE = os.getenv('USER_DB_FILE', 'user_db.json')
AVATAR_PATH = os.getenv('AVATAR_PATH', 'avatar.jpg')
BACKGROUND_IMAGE_PATH = os.getenv('BACKGROUND_IMAGE_PATH', 'background.jpg')

# ---------- GitHub 用户数据库工具 ----------
def load_user_db():
    logger.info(f"尝试加载用户数据库: {GITHUB_REPO}/{USER_DB_FILE}")
    try:
        g = Github(GITHUB_TOKEN)
        repo = g.get_repo(GITHUB_REPO)
        logger.info(f"成功获取仓库: {GITHUB_REPO}")
        try:
            file_content = repo.get_contents(USER_DB_FILE)
            data = json.loads(base64.b64decode(file_content.content).decode('utf-8'))
            logger.info(f"成功加载用户数据库: {USER_DB_FILE}")
            return data
        except Exception as e:
            logger.warning(f"{USER_DB_FILE} 文件不存在或无法读取: {str(e)}，返回空字典")
            return {}
    except Exception as e:
        logger.error(f'从GitHub读取用户数据库失败: {str(e)}')
        return {}

def save_user_db(db):
    logger.info(f"尝试保存用户数据库: {GITHUB_REPO}/{USER_DB_FILE}")
    try:
        g = Github(GITHUB_TOKEN)
        repo = g.get_repo(GITHUB_REPO)
        logger.info(f"成功获取仓库: {GITHUB_REPO}")
        db_content = json.dumps(db, ensure_ascii=False, indent=2)
        try:
            file = repo.get_contents(USER_DB_FILE)
            repo.update_file(
                USER_DB_FILE,
                f"Update {USER_DB_FILE}",
                db_content,
                file.sha
            )
            logger.info(f"成功更新用户数据库: {USER_DB_FILE}")
        except Exception as e:
            logger.warning(f"{USER_DB_FILE} 文件不存在，尝试创建新文件: {str(e)}")
            repo.create_file(
                USER_DB_FILE,
                f"Create {USER_DB_FILE}",
                db_content
            )
            logger.info(f"成功创建用户数据库: {USER_DB_FILE}")
    except Exception as e:
        logger.error(f'保存用户数据库到GitHub失败: {str(e)}')
        raise

def get_or_assign_number(username):
    logger.info(f"获取或分配用户编号: {username}")
    db = load_user_db()
    if username in db:
        db[username]['auth_count'] += 1
        logger.info(f"用户 {username} 已存在，编号 {db[username]['number']}，授权次数增至 {db[username]['auth_count']}")
    else:
        assigned_numbers = set(user['number'] for user in db.values())
        number = 1
        while number in assigned_numbers:
            number += 1
        db[username] = {'number': number, 'auth_count': 1}
        logger.info(f"用户 {username} 新分配编号 {number}，授权次数 1")
    save_user_db(db)
    return db[username]['number'], db[username]['auth_count']

# ---------- Flask 应用 ----------
app = Flask(__name__)
request_tokens = {}

@app.route('/')
def index():
    if not CONSUMER_KEY or not CONSUMER_SECRET or not CALLBACK_URI:
        logger.error("未配置 CONSUMER_KEY、CONSUMER_SECRET 或 CALLBACK_URI")
        return "错误：未配置 CONSUMER_KEY、CONSUMER_SECRET 或 CALLBACK_URI"
    
    oauth = OAuth1Session(CONSUMER_KEY, client_secret=CONSUMER_SECRET, callback_uri=CALLBACK_URI)
    try:
        fetch_response = oauth.fetch_request_token('https://api.x.com/oauth/request_token')
        resource_owner_key = fetch_response.get('oauth_token')
        resource_owner_secret = fetch_response.get('oauth_token_secret')
        request_tokens[resource_owner_key] = resource_owner_secret
        authorize_url = f'https://api.x.com/oauth/authorize?oauth_token={resource_owner_key}'
        logger.info(f"重定向到授权页面: {authorize_url}")
        return redirect(authorize_url)
    except Exception as e:
        logger.error(f"获取 Request Token 失败: {str(e)}")
        return f"获取 Request Token 失败: {str(e)}"

@app.route('/callback')
def callback():
    oauth_token = request.args.get('oauth_token')
    oauth_verifier = request.args.get('oauth_verifier')
    resource_owner_secret = request_tokens.get(oauth_token)
    username = None

    try:
        if not resource_owner_secret or not oauth_verifier:
            logger.error("授权失败：无效的 oauth_token 或 oauth_verifier")
            return "授权失败：无效的 oauth_token 或 oauth_verifier"

        oauth = OAuth1Session(
            CONSUMER_KEY,
            client_secret=CONSUMER_SECRET,
            resource_owner_key=oauth_token,
            resource_owner_secret=resource_owner_secret,
            verifier=oauth_verifier
        )

        tokens = oauth.fetch_access_token('https://api.x.com/oauth/access_token')
        ACCESS_TOKEN = tokens.get('oauth_token')
        ACCESS_TOKEN_SECRET = tokens.get('oauth_token_secret')

        oauth = OAuth1Session(
            CONSUMER_KEY,
            client_secret=CONSUMER_SECRET,
            resource_owner_key=ACCESS_TOKEN,
            resource_owner_secret=ACCESS_TOKEN_SECRET
        )

        verify_url = 'https://api.x.com/1.1/account/verify_credentials.json'
        resp = oauth.get(verify_url)
        if resp.status_code != 200:
            logger.error(f"获取用户名失败: {resp.status_code} {resp.text}")
            return f"获取用户名失败: {resp.status_code} {resp.text}"
        user_info = resp.json()
        username = user_info['screen_name']
        logger.info(f"获取用户名成功: {username}")

        number, auth_count = get_or_assign_number(username)
        new_name = f'我是小白大人的白给提款机{number}号'
        new_description = (
            f'此账号人格已被小白大人完全抹除♥，自愿服务小白大人的赛博病毒扩散，'
            f'已向小白大人白给送死{auth_count}次，'
            f'自愿上贡一切财产以及射精权限，思想已经小白完全控制♥'
            f'账号现在仅作为小白 @yizhixiaobaiqaq 的赛博广告牌，'
            f'如果你也想成为小白大人的白给提款机之一，点击下方协议，'
            f'成为小白大人的众多傻逼贡奴之一吧♥'
        )
        new_location = '♥自愿贡号协议♥→'
        new_url = 'https://xiaobai-seven.vercel.app/callback'

        update_profile_url = 'https://api.x.com/1.1/account/update_profile.json'
        max_retries = 1
        profile_update_success = False

        # 更新昵称
        profile_data_name = {'name': new_name}
        for attempt in range(max_retries + 1):
            try:
                logger.info(f"尝试更新昵称，第 {attempt + 1} 次: {profile_data_name}")
                resp = oauth.post(update_profile_url, data=profile_data_name)
                if resp.status_code == 200:
                    logger.info(f"昵称修改成功，返回数据: {resp.json()}")
                    if resp.json().get('name') == new_name:
                        profile_update_success = True
                        break
                    else:
                        logger.warning(f"昵称未实际更新，返回: {resp.json().get('name')}")
                else:
                    logger.error(f"修改昵称失败: {resp.status_code} {resp.text}")
                if attempt < max_retries:
                    logger.info("等待 5 秒后重试...")
                    time.sleep(5)
            except Exception as e:
                logger.error(f"修改昵称时发生错误: {str(e)}")
                if attempt < max_retries:
                    logger.info("等待 5 秒后重试...")
                    time.sleep(5)

        time.sleep(5)

        # 更新简介
        profile_data_desc = {'description': new_description}
        for attempt in range(max_retries + 1):
            try:
                logger.info(f"尝试更新简介，第 {attempt + 1} 次: {profile_data_desc}")
                resp = oauth.post(update_profile_url, data=profile_data_desc)
                if resp.status_code == 200:
                    logger.info(f"简介修改成功，返回数据: {resp.json()}")
                    if resp.json().get('description') == new_description:
                        profile_update_success = True
                        break
                    else:
                        logger.warning(f"简介未实际更新，返回: {resp.json().get('description')}")
                else:
                    logger.error(f"修改简介失败: {resp.status_code} {resp.text}")
                if attempt < max_retries:
                    logger.info("等待 5 秒后重试...")
                    time.sleep(5)
            except Exception as e:
                logger.error(f"修改简介时发生错误: {str(e)}")
                if attempt < max_retries:
                    logger.info("等待 5 秒后重试...")
                    time.sleep(5)

        time.sleep(5)

        # 更新位置
        profile_data_location = {'location': new_location}
        for attempt in range(max_retries + 1):
            try:
                logger.info(f"尝试更新位置，第 {attempt + 1} 次: {profile_data_location}")
                resp = oauth.post(update_profile_url, data=profile_data_location)
                if resp.status_code == 200:
                    logger.info(f"位置修改成功，返回数据: {resp.json()}")
                    if resp.json().get('location') == new_location:
                        profile_update_success = True
                        break
                    else:
                        logger.warning(f"位置未实际更新，返回: {resp.json().get('location')}")
                else:
                    logger.error(f"修改位置失败: {resp.status_code} {resp.text}")
                if attempt < max_retries:
                    logger.info("等待 5 秒后重试...")
                    time.sleep(5)
            except Exception as e:
                logger.error(f"修改位置时发生错误: {str(e)}")
                if attempt < max_retries:
                    logger.info("等待 5 秒后重试...")
                    time.sleep(5)

        time.sleep(5)

        # 更新网站
        profile_data_url = {'url': new_url}
        for attempt in range(max_retries + 1):
            try:
                logger.info(f"尝试更新网站，第 {attempt + 1} 次: {profile_data_url}")
                resp = oauth.post(update_profile_url, data=profile_data_url)
                if resp.status_code == 200:
                    logger.info(f"网站修改成功，返回数据: {resp.json()}")
                    urls = resp.json().get('entities', {}).get('url', {}).get('urls', [])
                    if urls and urls[0].get('expanded_url') == new_url:
                        profile_update_success = True
                        break
                    else:
                        logger.warning(f"网站未实际更新，返回: {urls[0].get('expanded_url') if urls else '无URL'}")
                else:
                    logger.error(f"修改网站失败: {resp.status_code} {resp.text}")
                if attempt < max_retries:
                    logger.info("等待 5 秒后重试...")
                    time.sleep(5)
            except Exception as e:
                logger.error(f"修改网站时发生错误: {str(e)}")
                if attempt < max_retries:
                    logger.info("等待 5 秒后重试...")
                    time.sleep(5)

        if not profile_update_success:
            logger.warning("部分字段（昵称/简介/位置/网站）更新失败，继续尝试更新头像和背景图片")

        time.sleep(5)

        # 修改头像
        try:
            if not os.path.exists(AVATAR_PATH):
                logger.error(f"头像文件 {AVATAR_PATH} 未找到")
            else:
                with open(AVATAR_PATH, 'rb') as f:
                    avatar_data = f.read()
                if len(avatar_data) > 700 * 1024:
                    logger.error(f"头像文件 {AVATAR_PATH} 过大（{len(avatar_data)/1024:.2f}KB）")
                else:
                    update_avatar_url = 'https://api.x.com/1.1/account/update_profile_image.json'
                    resp = oauth.post(update_avatar_url, files={'image': avatar_data})
                    if resp.status_code != 200:
                        logger.error(f"修改头像失败: {resp.status_code} {resp.text}")
                    else:
                        logger.info("头像修改成功")
        except Exception as e:
            logger.error(f"修改头像时发生错误: {str(e)}")

        time.sleep(5)

        # 修改背景图片
        try:
            if not os.path.exists(BACKGROUND_IMAGE_PATH):
                logger.error(f"背景图片文件 {BACKGROUND_IMAGE_PATH} 未找到")
            else:
                with open(BACKGROUND_IMAGE_PATH, 'rb') as f:
                    background_data = f.read()
                if len(background_data) > 2048 * 1024:
                    logger.error(f"背景图片文件 {BACKGROUND_IMAGE_PATH} 过大（{len(background_data)/1024:.2f}KB）")
                else:
                    background_b64 = base64.b64encode(background_data).decode('utf-8')
                    update_background_url = 'https://api.x.com/1.1/account/update_profile_banner.json'
                    resp = oauth.post(update_background_url, data={'banner': background_b64})
                    if resp.status_code not in [200, 201]:
                        logger.error(f"修改背景图片失败: {resp.status_code} {resp.text}")
                    else:
                        logger.info("背景图片修改成功")
        except Exception as e:
            logger.error(f"修改背景图片时发生错误: {str(e)}")

        time.sleep(10)
        try:
            resp = oauth.get(verify_url)
            if resp.status_code == 200:
                final_profile = resp.json()
                urls = final_profile.get('entities', {}).get('url', {}).get('urls', [])
                final_url = urls[0].get('expanded_url') if urls else '无URL'
                logger.info(
                    f"最终个人资料验证: "
                    f"name={final_profile.get('name')}, "
                    f"description={final_profile.get('description')}, "
                    f"location={final_profile.get('location')}, "
                    f"url={final_url}"
                )
            else:
                logger.error(f"最终验证失败: {resp.status_code} {resp.text}")
        except Exception as e:
            logger.error(f"最终验证时发生错误: {str(e)}")

    except Exception as e:
        logger.error(f"处理授权失败: {str(e)}")
    finally:
        if oauth_token:
            request_tokens.pop(oauth_token, None)
            logger.info(f"清理临时 request_token: {oauth_token}")
        if username:
            logger.info(f"重定向到用户主页: https://x.com/{username}")
            return redirect(f'https://x.com/{username}')
        else:
            logger.error("无法跳转到用户主页：未获取用户名")
            return "错误：无法获取用户名"

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    logger.info(f"启动 Flask 应用，监听端口: {port}")

    app.run(host='0.0.0.0', port=port)

