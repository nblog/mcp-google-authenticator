#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
Google Authenticator Plugin for MCP Service

This plugin provides functionalities for:
1. Parsing Google Authenticator migration URLs (otpauth-migration://)
2. Converting migration data to standard otpauth URLs
3. Generating TOTP tokens from otpauth URLs or secrets
4. Batch processing of multiple OTP accounts
"""

import hmac
import base64
import struct
import hashlib
import time
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, unquote
from enum import IntEnum

from semantic_kernel.functions import kernel_function

logger = logging.getLogger(__name__)


class Algorithm(IntEnum):
    """OTP算法枚举"""
    ALGORITHM_UNSPECIFIED = 0
    ALGORITHM_SHA1 = 1
    ALGORITHM_SHA256 = 2
    ALGORITHM_SHA512 = 3
    ALGORITHM_MD5 = 4


class DigitCount(IntEnum):
    """OTP位数枚举"""
    DIGIT_COUNT_UNSPECIFIED = 0
    DIGIT_COUNT_SIX = 1
    DIGIT_COUNT_EIGHT = 2


class OtpType(IntEnum):
    """OTP类型枚举"""
    OTP_TYPE_UNSPECIFIED = 0
    OTP_TYPE_HOTP = 1
    OTP_TYPE_TOTP = 2


class OtpParameters:
    """OTP参数类"""
    
    def __init__(self):
        self.secret: bytes = b''
        self.name: str = ''
        self.issuer: str = ''
        self.algorithm: Algorithm = Algorithm.ALGORITHM_SHA1
        self.digits: DigitCount = DigitCount.DIGIT_COUNT_SIX
        self.type: OtpType = OtpType.OTP_TYPE_TOTP
        self.counter: int = 0
    
    def get_algorithm_name(self) -> str:
        """获取算法名称"""
        algorithm_names = {
            Algorithm.ALGORITHM_UNSPECIFIED: "SHA1",
            Algorithm.ALGORITHM_SHA1: "SHA1",
            Algorithm.ALGORITHM_SHA256: "SHA256",
            Algorithm.ALGORITHM_SHA512: "SHA512",
            Algorithm.ALGORITHM_MD5: "MD5",
        }
        return algorithm_names.get(self.algorithm, "SHA1")
    
    def get_digit_count(self) -> int:
        """获取位数"""
        digit_counts = {
            DigitCount.DIGIT_COUNT_UNSPECIFIED: 6,
            DigitCount.DIGIT_COUNT_SIX: 6,
            DigitCount.DIGIT_COUNT_EIGHT: 8,
        }
        return digit_counts.get(self.digits, 6)
    
    def get_type_name(self) -> str:
        """获取OTP类型名称"""
        type_names = {
            OtpType.OTP_TYPE_UNSPECIFIED: "totp",
            OtpType.OTP_TYPE_HOTP: "hotp",
            OtpType.OTP_TYPE_TOTP: "totp",
        }
        return type_names.get(self.type, "totp")
    
    def get_secret_string(self) -> str:
        """将密钥转换为base32字符串"""
        return base64.b32encode(self.secret).decode('utf-8').rstrip('=')
    
    def to_otpauth_url(self) -> str:
        """转换为otpauth URL格式"""
        from urllib.parse import urlencode, quote
        
        # 构建查询参数
        params = {'secret': self.get_secret_string()}
        
        # 添加发行者（强烈建议）
        if self.issuer:
            params['issuer'] = self.issuer
        
        # 添加算法（可选）
        if self.algorithm != Algorithm.ALGORITHM_UNSPECIFIED:
            params['algorithm'] = self.get_algorithm_name()
        
        # 添加位数（可选）
        if self.digits != DigitCount.DIGIT_COUNT_UNSPECIFIED:
            params['digits'] = str(self.get_digit_count())
        
        # HOTP需要计数器
        if self.type == OtpType.OTP_TYPE_HOTP:
            params['counter'] = str(self.counter)
        
        # TOTP添加周期（可选，默认30秒）
        if self.type == OtpType.OTP_TYPE_TOTP:
            params['period'] = '30'
        
        # 构建URL
        query = urlencode(params)
        return f"otpauth://{self.get_type_name()}/{quote(self.name)}?{query}"


class GoogleAuthenticatorPlugin:
    """Google Authenticator MCP Plugin"""

    def __init__(self):
        self.logger = logger

    @staticmethod
    def _normalize_secret(key: str) -> str:
        """标准化密钥，移除空格并补充等号到8的倍数"""
        k2 = key.strip().replace(' ', '')
        if len(k2) % 8 != 0:
            k2 += '=' * (8 - len(k2) % 8)
        return k2

    @staticmethod
    def _prefix_zeros(h: str, digits: int = 6) -> str:
        """为代码补充前导零"""
        if len(h) < digits:
            h = '0' * (digits - len(h)) + h
        return h

    def _get_hotp_token(self, secret: str, intervals_no: int, algorithm: str = 'SHA1', digits: int = 6) -> str:
        """生成HOTP令牌"""
        # 选择哈希算法
        if algorithm.upper() == 'SHA1':
            hash_func = hashlib.sha1
        elif algorithm.upper() == 'SHA256':
            hash_func = hashlib.sha256
        elif algorithm.upper() == 'SHA512':
            hash_func = hashlib.sha512
        else:
            raise ValueError(f"不支持的算法: {algorithm}")
        
        key = base64.b32decode(self._normalize_secret(secret), True)
        msg = struct.pack(">Q", intervals_no)
        h = bytearray(hmac.new(key, msg, hash_func).digest())
        o = h[-1] & 15
        h = str((struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % (10 ** digits))
        return self._prefix_zeros(h, digits)

    def _get_totp_token(self, secret: str, period: int = 30, algorithm: str = 'SHA1', digits: int = 6) -> str:
        """生成TOTP令牌"""
        return self._get_hotp_token(secret, intervals_no=int(time.time())//period, algorithm=algorithm, digits=digits)

    def _parse_otpauth_url(self, url: str) -> Dict[str, Any]:
        """解析otpauth URL并提取参数"""
        parsed = urlparse(url)
        
        if parsed.scheme != 'otpauth':
            raise ValueError("无效的OTP URL格式")
        
        otp_type = parsed.netloc  # totp 或 hotp
        label = unquote(parsed.path.lstrip('/'))
        
        # 解析查询参数
        params = parse_qs(parsed.query)
        
        # 提取参数，使用默认值
        secret = params.get('secret', [None])[0]
        if not secret:
            raise ValueError("密钥是必需的")
        
        algorithm = params.get('algorithm', ['SHA1'])[0]
        digits = int(params.get('digits', ['6'])[0])
        period = int(params.get('period', ['30'])[0])
        
        return {
            'type': otp_type,
            'label': label,
            'secret': secret,
            'algorithm': algorithm,
            'digits': digits,
            'period': period
        }

    def _extract_migration_data(self, link: str) -> bytes:
        """从otpauth-migration URL中提取base64编码的数据"""
        parsed = urlparse(link)
        
        if parsed.scheme != 'otpauth-migration':
            raise ValueError(f"无效的协议: {parsed.scheme}, 期望 'otpauth-migration'")
        
        if parsed.netloc != 'offline':
            raise ValueError(f"无效的主机: {parsed.netloc}, 期望 'offline'")
        
        query_params = parse_qs(parsed.query)
        data_param = query_params.get('data')
        if not data_param:
            raise ValueError("URL中缺少 'data' 参数")
        
        data_str = data_param[0]
        # 修复空格为加号（URL解码可能会将+转换为空格）
        data_str = data_str.replace(' ', '+')
        
        try:
            return base64.b64decode(data_str)
        except Exception as e:
            raise ValueError(f"解码base64数据失败: {e}")

    def _decode_varint(self, data: bytes, offset: int) -> tuple[int, int]:
        """解码protobuf varint"""
        result = 0
        shift = 0
        while offset < len(data):
            byte = data[offset]
            offset += 1
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        return result, offset

    def _decode_length_delimited(self, data: bytes, offset: int) -> tuple[bytes, int]:
        """解码length-delimited字段"""
        length, offset = self._decode_varint(data, offset)
        field_data = data[offset:offset + length]
        return field_data, offset + length

    def _parse_otp_parameters(self, data: bytes) -> OtpParameters:
        """解析OtpParameters protobuf消息"""
        otp = OtpParameters()
        offset = 0
        
        while offset < len(data):
            # 读取字段标签
            tag, offset = self._decode_varint(data, offset)
            field_number = tag >> 3
            wire_type = tag & 0x7
            
            if field_number == 1:  # secret (bytes)
                if wire_type == 2:  # length-delimited
                    otp.secret, offset = self._decode_length_delimited(data, offset)
            elif field_number == 2:  # name (string)
                if wire_type == 2:  # length-delimited
                    name_bytes, offset = self._decode_length_delimited(data, offset)
                    otp.name = name_bytes.decode('utf-8')
            elif field_number == 3:  # issuer (string)
                if wire_type == 2:  # length-delimited
                    issuer_bytes, offset = self._decode_length_delimited(data, offset)
                    otp.issuer = issuer_bytes.decode('utf-8')
            elif field_number == 4:  # algorithm (enum)
                if wire_type == 0:  # varint
                    algorithm_value, offset = self._decode_varint(data, offset)
                    otp.algorithm = Algorithm(algorithm_value)
            elif field_number == 5:  # digits (enum)
                if wire_type == 0:  # varint
                    digits_value, offset = self._decode_varint(data, offset)
                    otp.digits = DigitCount(digits_value)
            elif field_number == 6:  # type (enum)
                if wire_type == 0:  # varint
                    type_value, offset = self._decode_varint(data, offset)
                    otp.type = OtpType(type_value)
            elif field_number == 7:  # counter (int64)
                if wire_type == 0:  # varint
                    otp.counter, offset = self._decode_varint(data, offset)
            else:
                # 跳过未知字段
                if wire_type == 0:  # varint
                    _, offset = self._decode_varint(data, offset)
                elif wire_type == 2:  # length-delimited
                    _, offset = self._decode_length_delimited(data, offset)
                else:
                    # 其他wire type暂不支持
                    break
        
        return otp

    def _parse_migration_payload(self, data: bytes) -> List[OtpParameters]:
        """解析Payload protobuf消息"""
        otp_parameters = []
        offset = 0
        
        while offset < len(data):
            # 读取字段标签
            tag, offset = self._decode_varint(data, offset)
            field_number = tag >> 3
            wire_type = tag & 0x7
            
            if field_number == 1:  # otp_parameters (repeated)
                if wire_type == 2:  # length-delimited
                    otp_data, offset = self._decode_length_delimited(data, offset)
                    otp_params = self._parse_otp_parameters(otp_data)
                    otp_parameters.append(otp_params)
            elif field_number == 2:  # version (int32)
                if wire_type == 0:  # varint
                    _, offset = self._decode_varint(data, offset)
            elif field_number == 3:  # batch_size (int32)
                if wire_type == 0:  # varint
                    _, offset = self._decode_varint(data, offset)
            elif field_number == 4:  # batch_index (int32)
                if wire_type == 0:  # varint
                    _, offset = self._decode_varint(data, offset)
            elif field_number == 5:  # batch_id (int32)
                if wire_type == 0:  # varint
                    _, offset = self._decode_varint(data, offset)
            else:
                # 跳过未知字段
                if wire_type == 0:  # varint
                    _, offset = self._decode_varint(data, offset)
                elif wire_type == 2:  # length-delimited
                    _, offset = self._decode_length_delimited(data, offset)
                else:
                    # 其他wire type暂不支持
                    break
        
        return otp_parameters

    @kernel_function(description="Parse Google Authenticator migration URL and convert it to a list of standard otpauth URLs with account details")
    def parse_migration_url(self, migration_url: str) -> str:
        """
        解析Google Authenticator迁移URL，返回otpauth URL列表
        
        Args:
            migration_url: otpauth-migration://offline?data=... 格式的迁移URL
        
        Returns:
            str: JSON格式的解析结果，包含账户列表和otpauth URL
        """
        try:
            self.logger.info(f"开始解析迁移URL: {migration_url[:50]}...")
            
            # 提取base64数据
            data = self._extract_migration_data(migration_url)
            
            # 解析protobuf数据
            otp_parameters = self._parse_migration_payload(data)
            
            # 转换为otpauth URL
            results = []
            for otp_params in otp_parameters:
                otpauth_url = otp_params.to_otpauth_url()
                
                account_info = {
                    'name': otp_params.name,
                    'issuer': otp_params.issuer,
                    'type': otp_params.get_type_name(),
                    'algorithm': otp_params.get_algorithm_name(),
                    'digits': otp_params.get_digit_count(),
                    'secret': otp_params.get_secret_string(),
                    'otpauth_url': otpauth_url
                }
                results.append(account_info)
            
            self.logger.info(f"成功解析 {len(results)} 个OTP账户")
            
            import json
            return json.dumps({
                'success': True,
                'accounts_count': len(results),
                'accounts': results
            }, ensure_ascii=False, indent=2)
            
        except Exception as e:
            self.logger.error(f"解析迁移URL失败: {e}")
            import json
            return json.dumps({
                'success': False,
                'error': str(e)
            }, ensure_ascii=False, indent=2)

    @kernel_function(description="Generate TOTP authentication code from either an otpauth URL or a base32 secret key")
    def generate_totp_token(self, secret_or_url: str, algorithm: str = "SHA1", digits: int = 6, period: int = 30) -> str:
        """
        生成TOTP验证码
        
        Args:
            secret_or_url: Base32密钥字符串或完整的otpauth URL
            algorithm: 哈希算法 (SHA1, SHA256, SHA512)
            digits: 验证码位数 (6或8)
            period: 时间周期（秒）
        
        Returns:
            str: JSON格式的结果，包含验证码和相关信息
        """
        try:
            self.logger.info(f"生成TOTP令牌，输入类型: {'URL' if secret_or_url.startswith('otpauth://') else '密钥'}")
            
            # 判断输入是URL还是密钥
            if secret_or_url.startswith('otpauth://'):
                # 解析otpauth URL
                params = self._parse_otpauth_url(secret_or_url)
                secret = params['secret']
                algorithm = params['algorithm']
                digits = params['digits']
                period = params['period']
                label = params['label']
            else:
                # 直接使用密钥
                secret = secret_or_url
                label = "Manual Entry"
            
            # 生成TOTP令牌
            token = self._get_totp_token(secret, period, algorithm, digits)
            
            # 计算剩余时间
            current_time = int(time.time())
            time_remaining = period - (current_time % period)
            
            self.logger.info(f"成功生成TOTP令牌: {token}")
            
            import json
            return json.dumps({
                'success': True,
                'token': token,
                'label': label,
                'algorithm': algorithm,
                'digits': digits,
                'period': period,
                'time_remaining': time_remaining,
                'generated_at': current_time
            }, ensure_ascii=False, indent=2)
            
        except Exception as e:
            self.logger.error(f"生成TOTP令牌失败: {e}")
            import json
            return json.dumps({
                'success': False,
                'error': str(e)
            }, ensure_ascii=False, indent=2)

    @kernel_function(description="Batch generate TOTP authentication codes for all accounts from a Google Authenticator migration URL")
    def generate_all_tokens_from_migration(self, migration_url: str) -> str:
        """
        从迁移URL批量生成所有账户的TOTP验证码
        
        Args:
            migration_url: otpauth-migration://offline?data=... 格式的迁移URL
        
        Returns:
            str: JSON格式的结果，包含所有账户的验证码
        """
        try:
            self.logger.info("开始批量生成TOTP令牌")
            
            # 首先解析迁移URL
            parse_result = self.parse_migration_url(migration_url)
            import json
            parsed_data = json.loads(parse_result)
            
            if not parsed_data.get('success'):
                return parse_result
            
            # 为每个账户生成TOTP令牌
            token_results = []
            for account in parsed_data['accounts']:
                try:
                    token_result = self.generate_totp_token(account['otpauth_url'])
                    token_data = json.loads(token_result)
                    
                    if token_data.get('success'):
                        token_results.append({
                            'name': account['name'],
                            'issuer': account['issuer'],
                            'token': token_data['token'],
                            'time_remaining': token_data['time_remaining'],
                            'algorithm': token_data['algorithm'],
                            'digits': token_data['digits']
                        })
                    else:
                        token_results.append({
                            'name': account['name'],
                            'issuer': account['issuer'],
                            'error': token_data.get('error', '未知错误')
                        })
                        
                except Exception as e:
                    token_results.append({
                        'name': account['name'],
                        'issuer': account['issuer'],
                        'error': str(e)
                    })
            
            self.logger.info(f"成功生成 {len(token_results)} 个账户的令牌")
            
            return json.dumps({
                'success': True,
                'total_accounts': len(token_results),
                'generated_at': int(time.time()),
                'tokens': token_results
            }, ensure_ascii=False, indent=2)
            
        except Exception as e:
            self.logger.error(f"批量生成TOTP令牌失败: {e}")
            import json
            return json.dumps({
                'success': False,
                'error': str(e)
            }, ensure_ascii=False, indent=2)

    # @kernel_function(description="Validate the correctness of an otpauth URL and extract its parameters")
    def validate_otpauth_url(self, otpauth_url: str) -> str:
        """
        验证otpauth URL的有效性并提取参数信息
        
        Args:
            otpauth_url: 要验证的otpauth URL
        
        Returns:
            str: JSON格式的验证结果
        """
        try:
            self.logger.info("验证otpauth URL")
            
            params = self._parse_otpauth_url(otpauth_url)
            
            # 尝试生成一个令牌来验证参数的有效性
            test_token = self._get_totp_token(
                params['secret'], 
                params['period'], 
                params['algorithm'], 
                params['digits']
            )
            
            import json
            return json.dumps({
                'success': True,
                'valid': True,
                'parameters': params,
                'test_token': test_token,
                'note': '验证成功，URL格式正确且可以生成有效令牌'
            }, ensure_ascii=False, indent=2)
            
        except Exception as e:
            self.logger.error(f"验证otpauth URL失败: {e}")
            import json
            return json.dumps({
                'success': False,
                'valid': False,
                'error': str(e)
            }, ensure_ascii=False, indent=2)