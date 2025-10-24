import base64
import json
import os
import time
from curl_cffi import requests
from decimal import Decimal, ROUND_DOWN
from eth_account import Account
from eth_account.messages import encode_typed_data, encode_defunct
from web3 import Web3
from loguru import logger
from multiprocessing.dummy import Pool
CONFIG = {
    "rpcUrl": "https://mainnet.base.org",
    "privateKey": "你的私钥 0x 开头",
    "x420TokenAddress": "0x5b30e6d93f5c50f92159394547b586b4e0047628",
    "UsdcAmount": "10",
    "threadCount": 30,
    "totalMintCount": 100000,
    "proxy":None
}

USDC_BASE_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
CHAIN_ID = 8453


# ============= EIP-712 结构 =============
EIP712_TYPES = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
        {"name": "verifyingContract", "type": "address"},
    ],
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ],
}

EIP712_DOMAIN = {
    "name": "USD Coin",
    "version": "2",
    "chainId": CHAIN_ID,
    "verifyingContract": USDC_BASE_ADDRESS,
}

PRIMARY_TYPE = "TransferWithAuthorization"

# ============= 工具函数 =============
def random_bytes32_hex() -> str:
    """生成 32 字节的 0x 前缀 hex 字符串"""
    return "0x" + os.urandom(32).hex()

def mint(thread_id: int):
    # 初始化账户
    if not CONFIG["privateKey"]:
        raise ValueError("请在 CONFIG['privateKey'] 中填入你的私钥（0x 开头）。")
    account = Account.from_key(CONFIG["privateKey"])
    logger.info(f"线程 {thread_id}: 使用账户 {account.address} 开始铸造。")
    # USDC 6 位小数
    usdc_amount_raw = Web3.to_wei(Decimal(CONFIG["UsdcAmount"]), "mwei")  # 6900000

    # 时间窗口
    max_timeout_seconds = 3000
    now_sec = int(time.time())
    valid_after = now_sec - 600
    valid_before = now_sec + max_timeout_seconds

    # 随机 32 字节 nonce（bytes32）
    nonce_hex32 = random_bytes32_hex()

    # EIP-712 message
    message = {
        "from": account.address,
        "to": CONFIG["x420TokenAddress"],
        "value": str(usdc_amount_raw),
        "validAfter": str(valid_after),
        "validBefore": str(valid_before),
        "nonce": nonce_hex32,
    }

    # 组装 typed data
    typed_data = {
        "types": EIP712_TYPES,
        "domain": EIP712_DOMAIN,
        "primaryType": PRIMARY_TYPE,
        "message": message,
    }

    # 签名（等价于 viem account.signTypedData）
    encoded_data = encode_typed_data(full_message=typed_data)
    signed_message = account.sign_message(encoded_data)
    signature = f"0x{signed_message.signature.hex()}"
    logger.info(f"线程 {thread_id}: 签名完成，发送交易中...")

    # 组装 payment JSON 并 base64
    payment = {
        "x402Version": 1,
        "scheme": "exact",
        "network": "base",
        "payload": {
            "signature": signature,
            "authorization": message,
        },
    }

    payload_str = json.dumps(payment, separators=(',', ':'), ensure_ascii=False)
    payment_base64 = base64.b64encode(payload_str.encode('utf-8')).decode('utf-8')
    # 发送
    result = send(payment_base64)
    if(result.get('requestId') is not None):
        logger.success(f"线程 {thread_id}: 铸造成功！requestId: {result['requestId']}=> {result}")
    else:
        logger.error(f"线程 {thread_id}: 铸造失败！结果: {result}")

def send(payment_base64: str, max_retries: int = 3):
    url = "https://pong.wtf/pong10"
    headers = {
        'accept': '*/*',
        'accept-language': 'zh-CN,zh;q=0.9',
        'access-control-expose-headers': 'X-PAYMENT-RESPONSE',
        'cache-control': 'no-cache',
        'pragma': 'no-cache',
        'priority': 'u=1, i',
        'referer': 'https://pong.wtf/pong10',
        'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"macOS"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
        'x-payment': payment_base64,
    }

    attempt = 0
    while attempt < max_retries:
        try:
            resp = requests.get(url, headers=headers, timeout=360,proxy=CONFIG["proxy"],impersonate="chrome136")
            text = resp.text
            logger.debug(text)
            if "failed to submit payment" in text.lower():
                return text
            # 返回 JSON（与原代码保持一致）
            try:
                return resp.json()
            except ValueError:
                # 非 JSON 则返回文本
                return resp.text
        except Exception as e:
            attempt += 1
            print(f"❌ 发送交易 (第 {attempt} 次): {e}")
            if attempt >= max_retries:
                print("🚨 已达到最大重试次数，推送失败。")
                return None
            time.sleep(0.1)



# 按装订区域中的绿色按钮以运行脚本。
if __name__ == "__main__":
    logger.warning("Author: 0xNaixi")
    logger.warning("Author: 0xNaixi")
    logger.warning("Author: 0xNaixi")
    logger.warning("https://x.com/0xNaiXi")
    logger.warning("验证码平台 https://www.nocaptcha.io/register?c=hLf08E")
    with Pool(CONFIG["threadCount"]) as pool:
        results = pool.map(mint, range(CONFIG["totalMintCount"]), chunksize=1)

# 访问 https://www.jetbrains.com/help/pycharm/ 获取 PyCharm 帮助
