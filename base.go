package rsas

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"text/template"
	"time"

	"github.com/astaxie/beego/httplib"
	"github.com/astaxie/beego/logs"
	"github.com/go-resty/resty/v2"
	jsoniter "github.com/json-iterator/go"
)

type rsas struct {
	username string
	passwd   string
	url      string
}

func New(_url, _user, _psd string) *rsas {
	return &rsas{
		username: _user,
		passwd:   _psd,
		url:      _url,
	}
}

func (c *rsas) RsasGet(_upath string) (map[string]interface{}, error) {
	req := httplib.Get(c.url+_upath).SetTimeout(100*time.Second, 30*time.Second)
	req.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	req.Param("username", c.username)
	req.Param("password", c.passwd)
	req.Param("formart", "json")
	var result map[string]interface{}
	err := req.ToJSON(&result)
	if err != nil {
		logs.Error("RsasGet", c.url, err)
	}
	return result, err
}

func (c *rsas) RsasPost(_upath string, Pam map[string]string) (map[string]interface{}, error) {
	req := httplib.Post(c.url+_upath).SetTimeout(100*time.Second, 30*time.Second)
	req.Param("username", c.username)
	req.Param("password", c.passwd)
	req.Param("formart", "json")
	req.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	for k, v := range Pam {
		req.Param(k, v)
	}
	var result map[string]interface{}
	err := req.ToJSON(&result)
	if err != nil {
		logs.Error("RastPost", c.url, err)
	}
	return result, err
}

func (c *rsas) RsasPostForm(_upath string, Pam, formPam map[string]string) (map[string]interface{}, error) {
	req := httplib.Post(c.url+_upath).SetTimeout(100*time.Second, 30*time.Second)
	req.Param("username", c.username)
	req.Param("password", c.passwd)
	req.Param("formart", "json")
	req.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	// 设置 proxy
	proxy_uri, _ := url.Parse("http://127.0.0.1:8080")
	req.SetProxy(http.ProxyURL(proxy_uri))
	//
	for k, v := range Pam {
		req.Param(k, v)
	}
	for k, v := range formPam {
		req.PostFile(k, v)
	}
	// println(req.String())
	var result map[string]interface{}
	err := req.ToJSON(&result)
	if err != nil {
		logs.Error("RastPost", c.url, err)
	}
	return result, err
}

// 获取系统状态
func (c *rsas) SysStatus() (map[string]interface{}, error) {
	uripath := "/api/system/status"
	re, err := c.RsasGet(uripath)
	return re, err
}

// 获取任务列表
func (c *rsas) TaskList() (map[string]interface{}, error) {
	uripath := "/api/task/list"
	re, err := c.RsasGet(uripath)
	return re, err
}

// 获取激活任务列表
func (c *rsas) ActiveList() (map[string]interface{}, error) {
	uripath := "/api/task/active_list"
	re, err := c.RsasGet(uripath)
	return re, err
}

// 获取任务状态
/*
{
  "data": {
    "id": 891,
    "name": "dududud ----",
    "process": 100,
    "status": 4,
    "time_end_scan": "2021-12-02 20:33:05",
    "time_start_scan": "2021-12-02 19:49:00",
    "user_account": "admin"
  },
  "ret_code": 0,
  "ret_msg": "success"
}
*/
func (c *rsas) TaskStatus(id string) (map[string]interface{}, error) {
	uripath := "/api/task/status/" + id
	re, err := c.RsasGet(uripath)
	return re, err
}

// 获取任务结果
func (c *rsas) TaskReport(id string) (map[string]interface{}, error) {
	uripath := "/api/report/task/" + id
	re, err := c.RsasPost(uripath, nil)
	return re, err
}

// 暂停任务
func (c *rsas) TaskPause(id string) (map[string]interface{}, error) {
	uripath := "/api/task/pause/" + id
	re, err := c.RsasPost(uripath, nil)
	return re, err
}

// 激活暂停任务
func (c *rsas) TaskResume(id string) (map[string]interface{}, error) {
	uripath := "/api/task/resume/" + id
	re, err := c.RsasPost(uripath, nil)
	return re, err
}

// 停止任务
func (c *rsas) TaskStop(id string) (map[string]interface{}, error) {
	uripath := "/api/task/stop/" + id
	re, err := c.RsasPost(uripath, nil)
	return re, err
}

// 删除任务
func (c *rsas) TaskDelete(id string) (map[string]interface{}, error) {
	uripath := "/api/task/delete/" + id
	re, err := c.RsasPost(uripath, nil)
	return re, err
}

// 获取漏洞模板
func (c *rsas) TaskTemplate() (map[string]interface{}, error) {
	uripath := "/api/template/sysvuln/list"
	re, err := c.RsasGet(uripath)
	return re, err
}

// 创建 简单扫描任务 【根据 template_id 控制 】
// 优先级未 中 不能定义各种信息
// 10 纯端口扫描（标准端口） 0 自动选择
func (c *rsas) TaskVulCreate(name, targets, template_id string) (map[string]interface{}, error) {
	uripath := "/api/task/vul/create"
	pam := make(map[string]string)
	pam["name"] = name
	pam["targets"] = targets
	if template_id == "" {
		template_id = "0"
	}
	pam["template_id"] = template_id
	re, err := c.RsasPost(uripath, pam)
	return re, err
}

// 创建评估任务 全端口扫描
func (c *rsas) TaskFullportScanCreate(name, targets string) (map[string]interface{}, error) {
	// 读取 xml 模板文件
	t1, err := template.ParseFiles("./libs/rsas/conf/fullportscan_1.xml")
	if err != nil {
		return nil, err
	}
	data := make(map[string]string)
	data["targets"] = targets
	data["port_strategy"] = "allports"
	data["taskname"] = name
	data["plugin_template_id"] = "10"
	buf := new(bytes.Buffer)
	t1.Execute(buf, data)
	// println(buf.String())
	str_buf := buf.String()
	notesBytes := []byte(str_buf)
	uripath := "/api/task/create?username=" + c.username + "&password=" + c.passwd + "&formart=json"
	json := jsoniter.ConfigCompatibleWithStandardLibrary

	client := resty.New()
	transport := &http.Transport{
		// Proxy: func(req *http.Request) (*url.URL, error) {
		// 	return url.Parse("http://127.0.0.1:8080")
		// },
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client.SetTransport(transport)
	result := make(map[string]interface{})

	resp, err := client.R().
		SetFileReader("config_xml", "text-file.txt", bytes.NewReader(notesBytes)).
		SetFormData(map[string]string{
			"type": "1",
		}).EnableTrace().
		Post(c.url + uripath)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(resp.Body(), &result)
	// libs.Printf_Color(result)
	return result, nil
}

func (c *rsas) TaskVulScanCreate(name, targets, ports string) (map[string]interface{}, error) {
	// 读取 xml 模板文件
	// t1, err := template.ParseFiles("./libs/rsas/conf/create_task_by_vul_1.xml")
	t1, err := template.ParseFiles("./conf/uservulscan_1.xml")
	//
	if err != nil {
		return nil, err
	}
	data := make(map[string]string)
	data["targets"] = targets
	// data["port_strategy"] = "allports"
	// eg : 1-88,99,100,5460
	data["userports"] = ports
	data["taskname"] = name
	data["plugin_template_id"] = "0"
	// 0 表示自动
	buf := new(bytes.Buffer)
	t1.Execute(buf, data)
	// println(buf.String())
	str_buf := buf.String()
	notesBytes := []byte(str_buf)
	uripath := "/api/task/create?username=" + c.username + "&password=" + c.passwd + "&formart=json"
	json := jsoniter.ConfigCompatibleWithStandardLibrary

	client := resty.New()
	transport := &http.Transport{
		// Proxy: func(req *http.Request) (*url.URL, error) {
		// 	return url.Parse("http://127.0.0.1:8080")
		// },
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client.SetTransport(transport)
	result := make(map[string]interface{})

	resp, err := client.R().
		SetFileReader("config_xml", "text-file.txt", bytes.NewReader(notesBytes)).
		SetFormData(map[string]string{
			"type": "1",
		}).EnableTrace().
		Post(c.url + uripath)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(resp.Body(), &result)
	// libs.Printf_Color(result)
	return result, nil
}

// test 创建评估任务 使用 beego.httplib
func (c *rsas) TaskMainCreateTest(_ty string) (map[string]interface{}, error) {
	// uripath := "/api/task/create?username=" + c.username + "&password=" + c.passwd + "&formart=json"
	uripath := "/api/task/create"
	pam := make(map[string]string)
	pam["type"] = _ty

	pam1 := make(map[string]string)
	pam1["config_xml"] = "./conf/create_task_by_vul_1.xml"

	// 使用代理正常、关闭代理失败
	re, err := c.RsasPostForm(uripath, pam, pam1)
	return re, err
}

// test 创建评估任务 使用 resty 库
func (c *rsas) TaskMainCreateResty(_ty string) (map[string]interface{}, error) {
	uripath := "/api/task/create?username=" + c.username + "&password=" + c.passwd + "&formart=json"
	// profileImgBytes, _ := ioutil.ReadFile("/Users/jeeva/test-img.png")
	notesBytes, _ := ioutil.ReadFile("./conf/create_task_by_vul_1.xml")

	// Create a Resty Client
	json := jsoniter.ConfigCompatibleWithStandardLibrary

	client := resty.New()
	transport := &http.Transport{
		// somthing like Proxying to httptest.Server, etc...
		// Proxy: func(req *http.Request) (*url.URL, error) {
		// 	return url.Parse("http://127.0.0.1:8080")
		// },
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client.SetTransport(transport)
	result := make(map[string]interface{})
	resp, err := client.R().
		// SetFileReader("profile_img", "test-img.png", bytes.NewReader(profileImgBytes)).
		SetFileReader("config_xml", "text-file.txt", bytes.NewReader(notesBytes)).
		SetFormData(map[string]string{
			"type": _ty,
			// "last_name":  "M",
		}).EnableTrace().
		Post(c.url + uripath)
	if err != nil {
		println(err.Error())
		// return nil, err
	}

	fmt.Println("Response Info:")
	fmt.Println("  Error      :", err)
	fmt.Println("  Status Code:", resp.StatusCode())
	fmt.Println("  Status     :", resp.Status())
	fmt.Println("  Proto      :", resp.Proto())
	fmt.Println("  Time       :", resp.Time())
	fmt.Println("  Received At:", resp.ReceivedAt())
	fmt.Println("  Body       :\n", resp)
	fmt.Println()

	ti := resp.Request.TraceInfo()
	fmt.Println("Request Trace Info:")
	fmt.Println("DNSLookup:", ti.DNSLookup)
	fmt.Println("ConnTime:", ti.ConnTime)
	fmt.Println("TCPConnTime:", ti.TCPConnTime)
	fmt.Println("TLSHandshake:", ti.TLSHandshake)
	fmt.Println("ServerTime:", ti.ServerTime)
	fmt.Println("ResponseTime:", ti.ResponseTime)
	fmt.Println("TotalTime:", ti.TotalTime)
	fmt.Println("IsConnReused:", ti.IsConnReused)
	fmt.Println("IsConnWasIdle:", ti.IsConnWasIdle)
	fmt.Println("ConnIdleTime:", ti.ConnIdleTime)
	fmt.Println("RequestAttempt:", ti.RequestAttempt)
	fmt.Println("RemoteAddr:", ti.RemoteAddr.String())

	_ = json.Unmarshal(resp.Body(), &result)
	// libs.Printf_Color(result)
	return result, nil

}
