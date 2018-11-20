package vcipher
import (
	"crypto/cipher"
    "crypto/aes"
    "crypto/rand"
	"bytes"
)

//AES aes编码，密码是随机的，size 是密码的长度
//  size int      密码的长度
//  cipher.Block  密码块对象
//  []byte        密码key
//  error         错误
func AES(size int) (cipher.Block, []byte, error) {
    buf := make([]byte, size)
    _, err := rand.Reader.Read(buf[:])
    if err != nil {
        return nil, nil, err
    }
    cipherBlock, err := aes.NewCipher(buf[:])
    if err != nil {
        return nil, nil, err
    }
    return cipherBlock, buf[:], nil
}

//密码
type Cipher struct {
    C   cipher.Block		//块对象
    Key []byte				//key密码
}

//NewCipher 密码对象
//  block cipher.Block		块对象
//  iv []byte				key密码
//  *Cipher					密码对象
func NewCipher(block cipher.Block, iv []byte) *Cipher {
    return &Cipher{
        C: block,
        Key: iv,
    }
}

//BlockSize 块大小
//  int	块大小
func (c *Cipher) BlockSize() int {
    return c.C.BlockSize()
}

//Encrypt 加密
//  dst []byte	目标，加密后的数据
//  src []byte	源，加密前的数据
func (c *Cipher) Encrypt(dst, src []byte){
	var(
		l		= len(src)
		size	= c.BlockSize()
		i 		= size
		j 		= 0
	)
	for ;;i+=size {
		c.C.Encrypt(dst[j:i] ,src[j:i])
		j = i
		if i >= l {
			break
		}
	}
}
//Decrypt 解密
//  dst []byte	目标，解密后的数据
//  src []byte	源，解密前的数据
func (c *Cipher) Decrypt(dst, src []byte) {
	var(
		l		= len(src)
		size	= c.BlockSize()
		i 		= size
		j 		= 0
	)
	for ;;i+=size {
		c.C.Decrypt(dst[j:i] ,src[j:i])
		j = i
		if i >= l {
			break
		}
	}
}

//CBCEncrypt CBC加密(密码块链接)
//  dst []byte	目标，加密后的数据
//  src []byte	源，加密前的数据
func (c *Cipher) CBCEncrypt(dst, src []byte) {
	cipherBlockMode := cipher.NewCBCEncrypter(c.C, c.Key)
	var(
		l		= len(src)
		size	= cipherBlockMode.BlockSize()
		i 		= size
		j 		= 0
	)
	for ;;i+=size {
		cipherBlockMode.CryptBlocks(dst[j:i] ,src[j:i])
		j = i
		if i >= l {
			break
		}
	}
}

//CBCDecrypt CBC解密(密码块链接)
//  dst []byte	目标，解密后的数据
//  src []byte	源，解密前的数据
func (c *Cipher) CBCDecrypt(dst, src []byte) {
	cipherBlockMode := cipher.NewCBCDecrypter(c.C, c.Key)
	var(
		l		= len(src)
		size	= cipherBlockMode.BlockSize()
		i 		= size
		j 		= 0
	)
	for ;;i+=size {
		cipherBlockMode.CryptBlocks(dst[j:i] ,src[j:i])
		j = i
		if i >= l {
			break
		}
	}
}

//Padding 填充
//  ciphertext []byte		填充文本，保证文本长度是密码的倍数。
func (c *Cipher) Padding(ciphertext []byte) []byte {
     padding := c.BlockSize() - len(ciphertext)%c.BlockSize()
     padtext := bytes.Repeat([]byte{byte(padding)}, padding)
     return append(ciphertext, padtext...)
}

//Unpadding 删除填充
//  origData []byte		去除填充文本结尾多余的数据，还原文本。
func (c *Cipher) Unpadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

//CFBEncrypt CFB加密(密码块反馈)
//  dst []byte	目标，加密后的数据
//  src []byte	源，加密前的数据
func (c *Cipher) CFBEncrypt(dst, src []byte) {
	cipherStream := cipher.NewCFBEncrypter(c.C, c.Key)
	cipherStream.XORKeyStream(dst, src)
}

//CFBDecrypt CFB解密(密码块反馈)
//  dst []byte	目标，解密后的数据
//  src []byte	源，解密前的数据
func (c *Cipher) CFBDecrypt(dst, src []byte) {
	cipherStream := cipher.NewCFBDecrypter(c.C, c.Key)
	cipherStream.XORKeyStream(dst, src)
}

//OFB OFB加密或解密(输出反馈)
//  dst []byte	目标，加密后或解密后的数据
//  src []byte	源，加密前或解密前的数据
func (c *Cipher) OFB(dst, src []byte) {
	cipherStream := cipher.NewOFB(c.C, c.Key)
	cipherStream.XORKeyStream(dst, src)
}

//CTR CTR加密或解密(计数器模式)
//  dst []byte	目标，加密后或解密后的数据
//  src []byte	源，加密前或解密前的数据
func (c *Cipher) CTR(dst, src []byte) {
	cipherStream := cipher.NewCTR(c.C, c.Key)
	cipherStream.XORKeyStream(dst, src)
}
