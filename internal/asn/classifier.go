package asn

import (
	"strings"
)

// IPType 常量定义
const (
	IPTypeDatacenter  = "datacenter"  // 机房 / 数据中心 / 云厂商
	IPTypeResidential = "residential" // 家庭宽带 / 住宅 ISP / 移动网络
)

// residentialASNs 知名全球与主要出海主流家庭宽带与电信运营商 ASN 集合
var residentialASNs = map[int]string{
	// 中国三大运营商家宽/骨干
	4134:   "China Telecom (Chinanet)",
	4809:   "China Telecom (CN2)",
	23724:  "China Telecom",
	134764: "China Telecom",
	134774: "China Telecom",
	134760: "China Telecom",
	4837:   "China Unicom (China169)",
	9929:   "China Unicom (CUII)",
	17621:  "China Unicom",
	17622:  "China Unicom",
	9808:   "China Mobile (CMNET)",
	56040:  "China Mobile",
	56041:  "China Mobile",
	56042:  "China Mobile",
	56046:  "China Mobile",
	17966:  "China Broadcasting Network / Great Wall",

	// 美国 / 北美主流家宽与移动 ISP
	7922:  "Comcast Cable Communications",
	20115: "Charter Communications (Spectrum)",
	10796: "Charter Communications",
	11427: "Charter Communications",
	12271: "Charter Communications",
	7018:  "AT&T Services",
	6389:  "AT&T BellSouth",
	7132:  "AT&T Internet Services",
	20057: "AT&T Mobility",
	701:   "Verizon Business",
	702:   "Verizon Internet Services",
	6167:  "Verizon Wireless",
	22773: "Cox Communications",
	209:   "CenturyLink / Lumen",
	21928: "T-Mobile USA",
	1239:  "Sprint",
	5650:  "Frontier Communications",
	852:   "Telus Communications (Canada)",
	577:   "Bell Canada",
	812:   "Rogers Communications (Canada)",

	// 中国香港 / 台湾
	9381:  "Hong Kong Broadband Network (HKBN)",
	4760:  "HKT Limited (PCCW)",
	24489: "SmarTone",
	3462:  "Data Communication Business Group (Chunghwa Telecom)",
	9924:  "Taiwan Fixed Network",
	9919:  "Taiwan Mobile",
	4780:  "Far EasTone Telecommunications",

	// 日本
	4713:  "NTT Plala / OCN",
	2514:  "NTT PC Communications",
	2516:  "KDDI Corporation (au Hikari)",
	17676: "Softbank Corp (Yahoo! BB)",
	4725:  "Softbank Corp",
	2518:  "Sony Network Communications (So-net)",
	17506: "J:COM Co., Ltd.",

	// 韩国
	4766: "Korea Telecom (KT)",
	9318: "SK Broadband",
	3786: "LG Uplus",

	// 欧洲主要宽带 ISP
	12353: "Vodafone GmbH",
	1273:  "Vodafone Group",
	3215:  "Orange S.A.",
	12322: "Free SAS / Proxad",
	15557: "SFR",
	2856:  "British Telecommunications (BT)",
	5089:  "Virgin Media",
	5607:  "Sky UK Limited",
	13285: "TalkTalk Communications",
	3269:  "Telecom Italia (TIM)",
	3352:  "Telefonica de Espana",
	12389: "Rostelecom",
	8359:  "MTS",
	// 德国
	3320:  "Deutsche Telekom",
	3209:  "Vodafone Deutschland (Kabel/DOCSIS)",
	8881:  "Vodafone Deutschland (DSL/Cable)",
	6805:  "Telefónica Germany (O2)",
	8560:  "1&1 Versatel",
	39706: "Deutsche Glasfaser",
	8422:  "NetCologne",
	8767:  "M-net Telekommunikations",
	9145:  "EWE TEL",
	15943: "wilhelm.tel",

	// 东南亚 / 澳洲
	7473: "Singapore Telecommunications (Singtel)",
	4657: "StarHub Ltd",
	4773: "M1 Limited",
	4788: "TM Net (Telekom Malaysia)",
	9534: "Maxis Broadband",
	1221: "Telstra Corporation",
	7474: "Optus Telecommunications",
	7545: "TPG Telecom Limited",
}

// residentialKeywords 家宽/宽带运营商关键词（小写）
var residentialKeywords = []string{
	"broadband",
	"cable",
	"telecom",
	"cellular",
	"mobile",
	"subscriber",
	"consumer",
	"residential",
	"fiber",
	"adsl",
	"ftth",
	"chinanet",
	"unicom",
	"cmnet",
	"comcast",
	"charter",
	"spectrum",
	"verizon",
	"softbank",
	"vodafone",
	"chunghwa",
	"telstra",
	"optus",
	"singtel",
	"starhub",
}

// datacenterOverrideKeywords 若同时包含这些词，说明属于云托管/IDC 部门，不误判为家宽
var datacenterOverrideKeywords = []string{
	"cloud",
	"hosting",
	"datacenter",
	"data center",
	"dedicated",
	"vps",
	"aws",
	"azure",
	"google cloud",
	"cloudflare",
	"fastly",
	"digitalocean",
	"hetzner",
	"ovh",
	"linode",
	"vultr",
	"leaseweb",
	"racknerd",
	"contabo",
}

// pureCDNASNs 知名全球纯商业 CDN 服务商自治系统 (Anycast / 反代，不适用于 REALITY 目标伪装)
var pureCDNASNs = map[int]string{
	13335:  "Cloudflare, Inc.",
	209242: "Cloudflare London",
	394536: "Cloudflare",
	395747: "Cloudflare",
	132892: "Cloudflare",
	133877: "Cloudflare",
	54113:  "Fastly, Inc.",
	20940:  "Akamai International B.V.",
	16625:  "Akamai Technologies, Inc.",
	32787:  "Akamai Prolexic",
	35994:  "Akamai Technologies",
	15133:  "EdgeCast / Verizon Media / Edgio",
	22822:  "Limelight Networks / Edgio",
	60068:  "CDN77 / Datacamp",
	19551:  "Imperva / Incapsula",
	199524: "Gcore CDN",
	203020: "BunnyCDN",
	135377: "UCSS / Cloudflare Partner",
}

var pureCDNKeywords = []string{
	"cloudflare",
	"fastly",
	"akamai",
	"incapsula",
	"imperva",
	"bunnycdn",
	"cdn77",
	"edgecast",
	"limelight networks",
}

// IsPureCDNASN 判断指定的 ASN 或组织名称是否属于纯商业 CDN 基础设施
func IsPureCDNASN(asnNum int, asnName ...string) (bool, string) {
	if name, ok := pureCDNASNs[asnNum]; ok {
		return true, name
	}
	if len(asnName) > 0 && asnName[0] != "" {
		nameLower := strings.ToLower(asnName[0])
		for _, kw := range pureCDNKeywords {
			if strings.Contains(nameLower, kw) {
				return true, asnName[0]
			}
		}
	}
	return false, ""
}

// ClassifyASN 判断指定的 ASN 是机房还是家庭宽带网络
// 简单粗暴规则：只要是已知家宽运营商/ISP 就当家宽 (residential)，其余一律当机房 (datacenter)
func ClassifyASN(asnNum int, asnName string) (ipType string, isResidential bool, providerName string) {
	// 1. 精确匹配已知家宽 ASN
	if name, ok := residentialASNs[asnNum]; ok {
		pName := asnName
		if pName == "" {
			pName = name
		}
		return IPTypeResidential, true, pName
	}

	nameLower := strings.ToLower(asnName)

	// 2. 检查是否为云厂商/IDC 强制覆盖词（如 "Alibaba Cloud Telecom", "Google Cloud" 等）
	for _, dcKey := range datacenterOverrideKeywords {
		if strings.Contains(nameLower, dcKey) {
			return IPTypeDatacenter, false, asnName
		}
	}

	// 3. 基于运营商名称关键词匹配家宽/电信特征
	for _, kw := range residentialKeywords {
		if strings.Contains(nameLower, kw) {
			return IPTypeResidential, true, asnName
		}
	}

	// 4. 其余一律归为机房 / 数据中心
	return IPTypeDatacenter, false, asnName
}

// TransitCountries 四大核心中转/线路机国家代码（美、港、日、德）
var TransitCountries = map[string]struct{}{
	"US": {},
	"HK": {},
	"JP": {},
	"DE": {},
}

// IsTransitCountry 检查国家代码是否属于美、港、日、德四大线路机核心国
func IsTransitCountry(country string) bool {
	_, ok := TransitCountries[strings.ToUpper(strings.TrimSpace(country))]
	return ok
}

// IsTransitDatacenterASN 判断指定的 ASN 是否为美/港/日/德纯机房（排除纯商业 CDN 与已知家宽）
func IsTransitDatacenterASN(asnNum int, country string, asnName string) bool {
	if !IsTransitCountry(country) {
		return false
	}
	if isCDN, _ := IsPureCDNASN(asnNum, asnName); isCDN {
		return false
	}
	if _, isResidential, _ := ClassifyASN(asnNum, asnName); isResidential {
		return false
	}
	return true
}

// CalculateASNPriority 根据国家、IDC/家宽分类、商业CDN特征计算 ASN 推荐初始扫描优先级与初始状态
func CalculateASNPriority(asnNum int, country string, asnName string, basePriority ...int) (priority int, scanStatus string) {
	// 1. 商业 CDN 基础设施：权重降为 0 并直接预设为 completed，防止全网扫描在 CDN 上做无用功
	if isCDN, _ := IsPureCDNASN(asnNum, asnName); isCDN {
		return 0, "completed"
	}

	// 2. 判断是否为家宽网络：家宽优先级降至低等级 (10 ~ 20)
	_, isResidential, _ := ClassifyASN(asnNum, asnName)
	if isResidential {
		return 10, "pending"
	}

	// 3. 纯机房：若属于美、港、日、德四大线路机核心国家，赋予最高调度优先级 (85 ~ 100)
	if IsTransitCountry(country) {
		p := 90
		if len(basePriority) > 0 && basePriority[0] > 0 {
			p = basePriority[0]
			if p < 85 {
				p = 85
			}
		}
		return p, "pending"
	}

	// 4. 国家未标注或未知
	if strings.TrimSpace(country) == "" {
		p := 20
		if len(basePriority) > 0 && basePriority[0] > 0 {
			p = basePriority[0]
		}
		return p, "pending"
	}

	// 5. 其他国家的纯机房：普通机房权重 (50 ~ 75)
	p := 50
	if len(basePriority) > 0 && basePriority[0] > 0 {
		p = basePriority[0]
		if p > 75 {
			p = 75
		}
	}
	return p, "pending"
}

