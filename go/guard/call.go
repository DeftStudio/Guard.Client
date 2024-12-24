package guard

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

type CheckCardParams struct {
	Msg        string `json:"msg"`
	DeviceCode string `json:"device_code"`
}

type UnBindingParams struct {
	Msg string `json:"msg"`
}

const chekckPath = "/api/check"
const unbindingPath = "/api/unbind"

type Client struct {
	Backend   string
	PublicKey *rsa.PublicKey
}

type Status struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

type Check struct {
	Sign        string `json:"sign"`
	Unix        int64  `json:"unix"`
	ProjectSign string `json:"project_sign"`
}

type Response struct {
	Status Status `json:"status"`
	Check  Check  `json:"check"`
}

func NewClient(key string, backend string) (*Client, error) {
	pubkey, err := parsePublicKey(key)
	if err != nil {
		return nil, err
	}
	return &Client{
		Backend:   backend,
		PublicKey: pubkey,
	}, nil
}

func (c *Client) encryptWithPublicKey(data string) (string, error) {
	plainText := []byte(data)
	encryptedBytes, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, c.PublicKey, plainText, nil)
	if err != nil {
		return "", fmt.Errorf("encryption error: %v", err)
	}
	encryptedData := base64.StdEncoding.EncodeToString(encryptedBytes)
	return encryptedData, nil
}

func (c *Client) Check(key, device string, projectName ...any) (time.Time, error) {
	msg, err := c.encryptWithPublicKey(key)
	if err != nil {
		return time.Time{}, err
	}
	checkCardParams := CheckCardParams{
		Msg:        msg,
		DeviceCode: device,
	}
	response, err := sendPostRequest(c.Backend+chekckPath, checkCardParams)
	if err != nil {
		return time.Time{}, err
	}
	if response.Status.Code != 1000 {
		return time.Time{}, errors.New("卡密校验失败。。。")
	}
	if err := c.verifySignatureWithPublicKey(key, response.Check.Sign); err != nil {
		return time.Time{}, errors.New("卡密校验失败，签名验证失败 err:" + err.Error())
	}
	if len(projectName) == 0 || projectName[0] == "" {
		projectName = append(projectName, "Default")
	}
	if err := c.verifySignatureWithPublicKey(fmt.Sprint(projectName[0]), response.Check.ProjectSign); err != nil {
		return time.Time{}, errors.New("卡密校验失败，项目验证失败 err:" + err.Error())
	}

	return time.Unix(response.Check.Unix, 0), nil
}

func (c *Client) UnBinding(key string) (time.Time, error) {
	msg, err := c.encryptWithPublicKey(key)
	if err != nil {
		return time.Time{}, err
	}
	unBindingParams := UnBindingParams{
		Msg: msg,
	}
	response, err := sendPostRequest(c.Backend+unbindingPath, unBindingParams)
	if err != nil {
		return time.Time{}, err
	}
	if response.Status.Code != 1000 {
		return time.Time{}, errors.New("卡密校验失败。。。")
	}
	if err := c.verifySignatureWithPublicKey(key, response.Check.Sign); err != nil {
		return time.Time{}, errors.New("卡密校验失败，签名验证失败 err:" + err.Error())
	}
	return time.Unix(response.Check.Unix, 0), nil
}

func parsePublicKey(pemString string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	var parsedKey interface{}
	if block.Type == "PUBLIC KEY" {
		var err error
		parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %v", err)
		}
	} else {
		return nil, fmt.Errorf("unknown PEM block type")
	}

	publicKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("parsed key is not an RSA public key")
	}

	return publicKey, nil
}

func (c *Client) verifySignatureWithPublicKey(data string, signature string) error {
	hashed := sha256.Sum256([]byte(data))
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("failed to decode base64 encoded signature: %v", err)
	}

	err = rsa.VerifyPKCS1v15(c.PublicKey, crypto.SHA256, hashed[:], signatureBytes)
	if err != nil {
		return fmt.Errorf("signature verification failed: %v", err)
	}

	return nil
}

func sendPostRequest(url string, params interface{}) (Response, error) {
	jsonData, err := json.Marshal(params)
	if err != nil {
		fmt.Println("编码 JSON 失败:", err)
		return Response{}, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return Response{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "客户端 IP 地址")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("请求失败:", err)
		return Response{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("读取响应失败:", err)
		return Response{}, err
	}

	if resp.StatusCode != 200 {
		return Response{}, errors.New("请求错误" + string(body))
	}

	var response Response
	err = json.Unmarshal(body, &response)
	if err != nil {
		fmt.Println("Error:", err)
		return Response{}, err
	}

	return response, nil
}
