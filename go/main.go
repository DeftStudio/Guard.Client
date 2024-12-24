package main

import (
	"fmt"
	"guard/guard"
)

var (
	api_url = "地址"
	key     = `
-----BEGIN PUBLIC KEY-----
密钥
-----END PUBLIC KEY-----
`
	// project = "Default"
)

func main() {
	if err := executeCheck(); err != nil {
		fmt.Println("Check error:", err)
	}

	if err := executeUnbinding(); err != nil {
		fmt.Println("Unbinding error:", err)
	}
}

func createClient() (*guard.Client, error) {
	// client, err := guard.NewClient(key, "地址")
	client, err := guard.NewClient(key, api_url)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func executeCheck() error {
	client, err := createClient()
	if err != nil {
		return err
	}

	// 卡密和设备码
	// 第三个参数为项目名称，不添加默认则是Default
	time, err := client.Check("cs-cs", "1")
	// time, err := client.Check("cs-cs", "1", project)
	// time, err := client.Check("cs-cs", "1", "as")
	if err != nil {
		return err
	}

	fmt.Println("Check有效期为:", time)
	return nil
}

func executeUnbinding() error {
	client, err := createClient()
	if err != nil {
		return err
	}

	// 卡密
	time, err := client.UnBinding("cs-cs")
	if err != nil {
		return err
	}

	fmt.Println("Unbinding有效期为:", time)
	return nil
}
