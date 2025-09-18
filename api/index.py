# -*- coding: utf-8 -*-
import os
import json
import base64
import time
import secrets
import hashlib
from flask import Flask, request, redirect, url_for, session
from requests_oauthlib import OAuth1Session, OAuth2Session
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
TARGET_TWEET_ID = "1959173416713646108"  # 目标推文 ID

# OAuth 2.0 配置
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
REDIRECT_URI_V2 = os.getenv('REDIRECT_URI_V2', f"{CALLBACK_URI.replace('/callback', '/callback/v2')}")
AUTHORIZATION_BASE_URL = 'https://x.com/i/oauth2/authorize'
TOKEN_URL = 'https://api.x.com/2/oauth2/token'

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
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(16))  # 更安全的密钥
request_tokens = {}

@app.route('/')
def index():
    if 'oauth_in_progress' in session and time.time() - session.get('oauth_start_time', 0) < 60:
        logger.info("检测到最近的授权流程，阻止重复请求")
        return redirect(session['oauth_authorize_url'])
    
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
        session['oauth_in_progress'] = True
        session['oauth_authorize_url'] = authorize_url
        session['oauth_start_time'] = time.time()
        logger.info(f"重定向到授权页面 (OAuth 1.0a): {authorize_url}")
        return redirect(authorize_url)
    except Exception as e:
        logger.error(f"获取 Request Token 失败: {str(e)}")
        return f"获取 Request Token 失败: {str(e)}"

@app.route('/callback')
def callback():
    oauth_token = request.args.get('oauth_token')
    oauth_verifier = request.args.get('oauth_verifier')
    state = request.args.get('state')
    code = request.args.get('code')

    # 如果存在 state 和 code，认为是 OAuth 2.0 回调，重定向到 /callback/v2
    if state and code:
        logger.info(f"检测到 OAuth 2.0 回调，state={state}, code={code}, 重定向到 /callback/v2")
        return redirect(url_for('callback_v2', state=state, code=code))

    resource_owner_secret = request_tokens.get(oauth_token)
    username = None

    try:
        logger.info(f"回调参数: oauth_token={oauth_token}, oauth_verifier={oauth_verifier}, resource_owner_secret={resource_owner_secret}")
        if not resource_owner_secret or not oauth_verifier:
            logger.error("授权失败：无效的 oauth_token 或 oauth_verifier")
            return "授权失败：无效的 oauth_token 或 oauth_verifier"

        # OAuth 1.0a 认证
        oauth1 = OAuth1Session(
            CONSUMER_KEY,
            client_secret=CONSUMER_SECRET,
            resource_owner_key=oauth_token,
            resource_owner_secret=resource_owner_secret,
            verifier=oauth_verifier
        )
        tokens = oauth1.fetch_access_token('https://api.x.com/oauth/access_token')
        ACCESS_TOKEN = tokens.get('oauth_token')
        ACCESS_TOKEN_SECRET = tokens.get('oauth_token_secret')

        oauth1 = OAuth1Session(
            CONSUMER_KEY,
            client_secret=CONSUMER_SECRET,
            resource_owner_key=ACCESS_TOKEN,
            resource_owner_secret=ACCESS_TOKEN_SECRET
        )

        verify_url = 'https://api.x.com/1.1/account/verify_credentials.json'
        resp = oauth1.get(verify_url)
        if resp.status_code != 200:
            logger.error(f"获取用户名失败: {resp.status_code} {resp.text}")
            return f"获取用户名失败: {resp.status_code} {resp.text}"
        user_info = resp.json()
        username = user_info['screen_name']
        logger.info(f"获取用户名成功 (OAuth 1.0a): {username}")

        number, auth_count = get_or_assign_number(username)
        new_name = f'xiaobai-pi.vercel.app'
        new_description = (
            f'此账号人格已被小白大人完全抹除♥，自愿服务小白大人的赛博病毒扩散，'
            f'已向小白大人白给送死{auth_count}次，'
            f'自愿上贡一切财产以及射精权限，思想已经小白完全控制♥'
            f'账号现在仅作为小白 @yizhixiaobaiqaq 的赛博广告牌，'
            f'如果你也想成为小白大人的白给提款机之一，点击下方协议，'
            f'成为小白大人的众多逼贡至一吧♥'
        )
        new_location = '♥自愿贡号协议♥→'
        new_url = 'xiaobai-pi.vercel.app'

        update_profile_url = 'https://api.x.com/1.1/account/update_profile.json'
        profile_update_success = False

        # 更新昵称
        profile_data_name = {'name': new_name}
        try:
            logger.info(f"尝试更新昵称: {profile_data_name}")
            resp = oauth1.post(update_profile_url, data=profile_data_name)
            if resp.status_code == 200:
                logger.info(f"昵称修改成功，返回数据: {resp.json()}")
                if resp.json().get('name') == new_name:
                    profile_update_success = True
                else:
                    logger.warning(f"昵称未实际更新，返回: {resp.json().get('name')}")
            else:
                logger.error(f"修改昵称失败: {resp.status_code} {resp.text}")
        except Exception as e:
            logger.error(f"修改昵称时发生错误: {str(e)}")
        time.sleep(1)

        # 更新简介
        profile_data_desc = {'description': new_description}
        try:
            logger.info(f"尝试更新简介: {profile_data_desc}")
            resp = oauth1.post(update_profile_url, data=profile_data_desc)
            if resp.status_code == 200:
                logger.info(f"简介修改成功，返回数据: {resp.json()}")
                if resp.json().get('description') == new_description:
                    profile_update_success = True
                else:
                    logger.warning(f"简介未实际更新，返回: {resp.json().get('description')}")
            else:
                logger.error(f"修改简介失败: {resp.status_code} {resp.text}")
        except Exception as e:
            logger.error(f"修改简介时发生错误: {str(e)}")
        time.sleep(1)

        # 更新位置
        profile_data_location = {'location': new_location}
        try:
            logger.info(f"尝试更新位置: {profile_data_location}")
            resp = oauth1.post(update_profile_url, data=profile_data_location)
            if resp.status_code == 200:
                logger.info(f"位置修改成功，返回数据: {resp.json()}")
                if resp.json().get('location') == new_location:
                    profile_update_success = True
                else:
                    logger.warning(f"位置未实际更新，返回: {resp.json().get('location')}")
            else:
                logger.error(f"修改位置失败: {resp.status_code} {resp.text}")
        except Exception as e:
            logger.error(f"修改位置时发生错误: {str(e)}")
        time.sleep(1)

        # 更新网站
        profile_data_url = {'url': new_url}
        try:
            logger.info(f"尝试更新网站: {profile_data_url}")
            resp = oauth1.post(update_profile_url, data=profile_data_url)
            if resp.status_code == 200:
                logger.info(f"网站修改成功，返回数据: {resp.json()}")
                urls = resp.json().get('entities', {}).get('url', {}).get('urls', [])
                if urls and urls[0].get('expanded_url') == new_url:
                    profile_update_success = True
                else:
                    logger.warning(f"网站未实际更新，返回: {urls[0].get('expanded_url') if urls else '无URL'}")
            else:
                logger.error(f"修改网站失败: {resp.status_code} {resp.text}")
        except Exception as e:
            logger.error(f"修改网站时发生错误: {str(e)}")
        time.sleep(1)

        if not profile_update_success:
            logger.warning("部分字段（昵称/简介/位置/网站）更新失败，继续尝试更新头像和背景图片")

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
                    resp = oauth1.post(update_avatar_url, files={'image': avatar_data})
                    if resp.status_code != 200:
                        logger.error(f"修改头像失败: {resp.status_code} {resp.text}")
                    else:
                        logger.info("头像修改成功")
        except Exception as e:
            logger.error(f"修改头像时发生错误: {str(e)}")
        time.sleep(1)

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
                    resp = oauth1.post(update_background_url, data={'banner': background_b64})
                    if resp.status_code not in [200, 201]:
                        logger.error(f"修改背景图片失败: {resp.status_code} {resp.text}")
                    else:
                        logger.info("背景图片修改成功")
        except Exception as e:
            logger.error(f"修改背景图片时发生错误: {str(e)}")
        time.sleep(1)

        # 新增：使用 OAuth 1.0a 发布推文
        tweet_text = (
            f"你好，你现在看到的是清秋女神的白给提款机之一，我已自愿签署上贡射精管理协议，不上贡就不配自慰获取快感，"
            f"只有清空余额才能射精的白给ATM，当你看到这里，如果勃起的话，那就握着下面，点击下面的链接查看签署协议，"
            f"成为清秋女神的众多白给钱包之一吧 https://x.com/qing_qiu9999/status/195917341671364"
        )
        if len(tweet_text) > 280:
            tweet_text = tweet_text[:277] + "..."  # 确保不超过280字符
        tweet_url = 'https://api.x.com/1.1/statuses/update.json'
        resp = oauth1.post(tweet_url, data={'status': tweet_text})
        if resp.status_code == 200:
            logger.info(f"成功发布推文，内容: {tweet_text}")
            # 验证推文是否实际发布
            timeline_url = 'https://api.x.com/1.1/statuses/user_timeline.json'
            resp = oauth1.get(timeline_url, params={'screen_name': username, 'count': 10})
            if resp.status_code == 200:
                tweets = resp.json()
                tweet_found = any(tweet['text'] == tweet_text for tweet in tweets)
                logger.info(f"推文验证: {'成功' if tweet_found else '未找到推文'}")
            else:
                logger.error(f"获取时间线失败: {resp.status_code} {resp.text}")
        else:
            logger.error(f"发布推文失败: {resp.status_code} {resp.text}")

        # 将 user_info 和 OAuth 1.0a 令牌存储到 session
        session['user_info'] = user_info
        session['access_token'] = ACCESS_TOKEN
        session['access_token_secret'] = ACCESS_TOKEN_SECRET

        # OAuth 2.0 认证（用于回复）
        code_verifier = secrets.token_urlsafe(32)  # 随机生成 43-128 字符的 code_verifier
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('ascii')).digest()
        ).decode('ascii').rstrip('=')
        oauth2 = OAuth2Session(
            CLIENT_ID,
            redirect_uri=REDIRECT_URI_V2,
            scope=['tweet.read', 'tweet.write', 'users.read']
        )
        authorization_url, state = oauth2.authorization_url(
            AUTHORIZATION_BASE_URL,
            code_challenge=code_challenge,
            code_challenge_method='S256'
        )
        session['oauth2_tokens'] = session.get('oauth2_tokens', {})
        session['oauth2_tokens'][state] = {'username': username, 'code_verifier': code_verifier}
        logger.info(f"OAuth 2.0 code_verifier={code_verifier}, code_challenge={code_challenge}")
        logger.info(f"重定向到 OAuth 2.0 授权页面: {authorization_url}")
        return redirect(authorization_url)

    except Exception as e:
        logger.error(f"处理授权失败 (OAuth 1.0a): {str(e)}")
    finally:
        if oauth_token and 'user_info' in session:  # 仅在成功处理后清理
            request_tokens.pop(oauth_token, None)
            logger.info(f"清理临时 request_token: {oauth_token}")
        session.pop('oauth_in_progress', None)
        session.pop('oauth_authorize_url', None)

@app.route('/callback/v2')
def callback_v2():
    state = request.args.get('state')
    code = request.args.get('code')
    oauth2 = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI_V2, state=state)
    try:
        oauth2_tokens = session.get('oauth2_tokens', {})
        token_data = oauth2_tokens.get(state, {})
        code_verifier = token_data.get('code_verifier')
        if not code_verifier:
            logger.error("未找到 code_verifier")
            return "错误：未找到 code_verifier"

        logger.info(f"OAuth 2.0 回调: state={state}, code={code}, code_verifier={code_verifier}")
        token = oauth2.fetch_token(
            TOKEN_URL,
            client_secret=CLIENT_SECRET,
            authorization_response=request.url,
            code_verifier=code_verifier
        )
        logger.info(f"成功获取 OAuth 2.0 访问令牌: {token['access_token']}")

        # 从 session 获取 user_info
        user_info = session.get('user_info')
        if not user_info:
            logger.error("未找到 user_info")
            return "错误：未找到用户资料"

        username = token_data.get('username')
        if not username:
            logger.error("未找到对应的用户名")
            return "错误：未找到对应的用户名"

        # 使用 OAuth 2.0 执行回复
        reply_url = 'https://api.x.com/2/tweets'
        number, auth_count = get_or_assign_number(username)
        reply_text = f"（白给提款机好喜欢清秋女神，我已自愿为清秋女神上贡账号{auth_count}次）"
        # 检查是否已有相同回复
        timeline_url = f'https://api.x.com/2/users/{user_info["id"]}/tweets'
        resp = oauth2.get(timeline_url, headers={'Authorization': f'Bearer {token["access_token"]}'})
        if resp.status_code == 200:
            tweets = resp.json().get('data', [])
            reply_found = any(tweet['text'] == reply_text and tweet.get('in_reply_to_status_id') == TARGET_TWEET_ID for tweet in tweets)
            if reply_found:
                logger.info(f"检测到已有相同回复，跳过发布")
            else:
                resp = oauth2.post(reply_url, json={'text': reply_text, 'reply': {'in_reply_to_tweet_id': TARGET_TWEET_ID}}, headers={'Authorization': f'Bearer {token["access_token"]}'})
                if resp.status_code == 201:
                    logger.info(f"成功回复推文 {TARGET_TWEET_ID}, 内容: {reply_text}")
                    # 验证回复是否实际发布
                    resp = oauth2.get(timeline_url, headers={'Authorization': f'Bearer {token["access_token"]}'})
                    if resp.status_code == 200:
                        tweets = resp.json().get('data', [])
                        reply_found = any(tweet['text'] == reply_text and tweet.get('in_reply_to_status_id') == TARGET_TWEET_ID for tweet in tweets)
                        logger.info(f"回复验证: {'成功' if reply_found else '未找到回复'}")
                    else:
                        logger.error(f"获取时间线失败: {resp.status_code} {resp.text}")
                else:
                    logger.error(f"回复失败: {resp.status_code} {resp.text}")
        else:
            logger.error(f"获取时间线失败: {resp.status_code} {resp.text}")

        # 最终验证（使用 OAuth 1.0a）
        oauth1 = OAuth1Session(
            CONSUMER_KEY,
            client_secret=CONSUMER_SECRET,
            resource_owner_key=session.get('access_token'),
            resource_owner_secret=session.get('access_token_secret')
        )
        verify_url = 'https://api.x.com/1.1/account/verify_credentials.json'
        resp = oauth1.get(verify_url)
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

        # 清理 session
        session.pop('user_info', None)
        session.pop('access_token', None)
        session.pop('access_token_secret', None)
        session.pop('oauth2_tokens', None)

        logger.info(f"重定向到用户主页: https://x.com/{username}")
        return redirect(f'https://x.com/{username}')
    
    except Exception as e:
        logger.error(f"OAuth 2.0 授权失败: {str(e)}")
        return f"OAuth 2.0 授权失败: {str(e)}"
    finally:
        oauth2_tokens = session.get('oauth2_tokens', {})
        if state in oauth2_tokens:
            oauth2_tokens.pop(state, None)
            session['oauth2_tokens'] = oauth2_tokens
            logger.info(f"清理临时 OAuth 2.0 state: {state}")
        if not oauth2_tokens:
            session.pop('oauth2_tokens', None)
            logger.info("清理所有 OAuth 2.0 tokens")

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    logger.info(f"启动 Flask 应用，监听端口: {port}")
    app.run(host='0.0.0.0', port=port)
