
# Name
`lua-resty-sm4` 在Lua中使用FFI库，调用OpenSSL库的函数，实现SM4对称加解密算法。

## SM4 encrypt demo
```lua

local sm4 = require "resty.sm4"

-- sm4 加密
-- plainText ： 明文字符
-- padding   ： 0-nopadding   7=pkcs7
-- key       ： key
-- mode      ： 默认是cbc
-- iv        ： 默认等于key
local function sm4_encrypt(plainText, padding, key, mode, iv)
    mode = mode or "cbc"
    padding = padding == 7 or false
    iv = iv or key
    local sm4Obj, err = sm4.new(key, nil, sm4.cipher(mode), { iv = iv }, nil, nil, padding)
    if err then
        return nil, err
    end
    local encrypted = sm4Obj:encrypt(plainText)
    return ngx.encode_base64(encrypted)
end
```

## SM4 decrypt demo
```lua
local sm4 = require "resty.sm4"
-- sm4 解密
-- plainText ： 明文字符
-- padding   ： 0-nopadding   7=pkcs7
-- key       ： key
-- mode      ： 默认是cbc
-- iv        ： 默认等于key
local function sm4_decrypt(ciphertext, padding, key, mode, iv)
    mode = mode or "cbc"
    padding = padding == 7 or false
    iv = iv or key
    local sm4Obj, err = sm4.new(key, nil, sm4.cipher(mode), { iv = iv }, nil, nil, padding)
    if err then
        return nil, err
    end

    ciphertext = ngx.decode_base64(ciphertext)
    return sm4Obj:decrypt(ciphertext)
end
```
