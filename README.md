# vcipher [![Build Status](https://travis-ci.org/456vv/vcipher.svg?branch=master)](https://travis-ci.org/456vv/vcipher)
golang vcipher，集成了常见的加密方法。

# **列表：**
```go
func AES(size int) (cipher.Block, []byte, error)            // AES编码
type Cipher struct {                                    // 密码
    C   cipher.Block		                                // 块对象
    Key []byte                                              // key密码
}
    func NewCipher(block cipher.Block, iv []byte) *Cipher   // 密码对象
    func (c *Cipher) BlockSize() int                        // 块大小
    func (c *Cipher) Encrypt(dst, src []byte)               // 加密
    func (c *Cipher) Decrypt(dst, src []byte)               // 解密
    func (c *Cipher) CBCEncrypt(dst, src []byte)            // CBC加密(密码块链接)
    func (c *Cipher) CBCDecrypt(dst, src []byte)            // CBC解密(密码块链接)
    func (c *Cipher) Padding(ciphertext []byte) []byte      // 填充增加
    func (c *Cipher) Unpadding(origData []byte) []byte      // 填充删除
    func (c *Cipher) CFBEncrypt(dst, src []byte)            // CFB加密(密码块反馈)，不需填充
    func (c *Cipher) CFBDecrypt(dst, src []byte)            // CFB解密(密码块反馈)，不需填充
    func (c *Cipher) OFB(dst, src []byte)                   // OFB加密或解密(输出反馈)，不需填充
    func (c *Cipher) CTR(dst, src []byte)                   // CTR加密或解密(计数器模式)，不需填充
```