#include <mgr/mgrrpc.h>
#include <ispbin.h>
#include <mgr/mgrlog.h>
#include <iostream>
#include <mgr/mgrdate.h>
#include <processing/processingmodule.h>
#include <processing/certificate_common.h>
#include <processing/domain_common.h>

using namespace processing;
using namespace opts;
using namespace std;

#define BINARY_NAME "pmopenprovider"
MODULE(BINARY_NAME);

#define CERTIFICATE_ALTNAME "altname"

namespace
{
	static string Get(const mgr_xml::XmlNode& p, const string& field)
	{
		auto c = p ? p.FindNode(field) : p;
		return c ? c.Str() : "";
	}
}

namespace processing
{
	string Transliterate(const string& arg);
	struct SslTemplate
	{
		string id;
		string name;
		bool wildcard = false;
		bool www = false;
		bool multidomain = false;
		bool idn = false;
		bool orginfo = false;
		bool codesign = false;
		bool csraltname = false;
	};

	class Openprovider : public Module
	{
		public:
			struct OrderInfo { string crt, expire, status; };
			struct DomainInfo { string domain; StringMap handles; StringVector ns; mgr_date::Date expire; };
		private:
			StringMap params;
			string itemtype;
			string pricelist;
			void Init(int iid);
			virtual void ProcessCommand();
			void SetParam(const int iid);

			mgr_xml::Xml Remote_GetOpenxml();
			mgr_xml::Xml Remote_Send(mgr_xml::Xml req);
			std::vector<SslTemplate> Remote_SslTemplates();
			StringVector Remote_SslApprovers(const string& domain, const string& cert);
			string Remote_CreateCertCustomer(const string& prefix);
			string Remote_CreateCert(bool doReissue = false);
			OrderInfo Remote_GetCert(const string& id);
			OrderInfo Remote_GetDomain(const string& id);
			string Remote_CreateDomainCustomer(const string& prefix);
			void Remote_CreateDomain(const string& action);
			std::vector<DomainInfo> Remote_SearchDomain(int limit, int offset, const StringMap &params, int *total = nullptr);
			void Remote_RenewDomain();
			std::vector<std::string> DomainHandleTypes() { return { "owner", "admin", "bill", "tech" }; };
			StringMap contact2handle;
			void RegisterDomainContacts();
			string StoreContact(const string& extid);

		protected:
			virtual int GetMaxTryCount(const std::string &operation);
			virtual void InternalAddItemParam(StringMap &params, const int iid);

		public:
			Openprovider():
				Module(BINARY_NAME)
			{
			}
			
			mgr_xml::Xml Features() override;
			
			void CheckConnection(mgr_xml::Xml module_xml)
			{
				STrace();
			}
			void Open(int) override;
			void Prolong(int) override;
			void Reopen(int) override;
			void Resume(int) override;
			void Suspend(int) override;
			void Close(int) override;
			void CheckParam(mgr_xml::Xml item_xml, const int item_id, const string& param_name, const string& value) override;
			void DumpSslTemplates(int module);
			mgr_xml::Xml ApproverList(const int mid, const string& domain, const string& intname);
			void SyncItem(int) override;
			mgr_xml::Xml GetContactType(const string& tld);
			void UpdateNS(int) override;
			void Import(const int mid, const string& itemtype, const string& search) override;
			void Transfer(int iid, StringMap&);
	};
}

static inline const wchar_t* TransliterateSymb(WCHAR c)
{
	switch (c)
	{
		case L'А': return L"A";
		case L'Б': return L"B";
		case L'В': return L"V";
		case L'Г': return L"G";
		case L'Д': return L"D";
		case L'Е': return L"E";
		case L'Ё': return L"Yo";
		case L'Ж': return L"J";
		case L'З': return L"Z";
		case L'И': return L"I";
		case L'Й': return L"J";
		case L'К': return L"K";
		case L'Л': return L"L";
		case L'М': return L"M";
		case L'Н': return L"N";
		case L'О': return L"O";
		case L'П': return L"P";
		case L'Р': return L"R";
		case L'С': return L"S";
		case L'Т': return L"T";
		case L'У': return L"U";
		case L'Ф': return L"F";
		case L'Х': return L"H";
		case L'Ц': return L"Ts";
		case L'Ч': return L"Ch";
		case L'Ш': return L"Sh";
		case L'Щ': return L"Sch";
		case L'Ъ': return L"";
		case L'Ы': return L"Y";
		case L'Ь': return L"";
		case L'Э': return L"E";
		case L'Ю': return L"Yu";
		case L'Я': return L"Ya";
		case L'а': return L"a";
		case L'б': return L"b";
		case L'в': return L"v";
		case L'г': return L"g";
		case L'д': return L"d";
		case L'е': return L"e";
		case L'ё': return L"yo";
		case L'ж': return L"j";
		case L'з': return L"z";
		case L'и': return L"i";
		case L'й': return L"j";
		case L'к': return L"k";
		case L'л': return L"l";
		case L'м': return L"m";
		case L'н': return L"n";
		case L'о': return L"o";
		case L'п': return L"p";
		case L'р': return L"r";
		case L'с': return L"s";
		case L'т': return L"t";
		case L'у': return L"u";
		case L'ф': return L"f";
		case L'х': return L"h";
		case L'ц': return L"ts";
		case L'ч': return L"ch";
		case L'ш': return L"sh";
		case L'щ': return L"sch";
		case L'ъ': return L"";
		case L'ы': return L"y";
		case L'ь': return L"";
		case L'э': return L"e";
		case L'ю': return L"yu";
		case L'я': return L"ya";
		default: return NULL;
	}
}

string processing::Transliterate(const string& arg)
{
	str::u16string ret;
	for (auto i : str::u16string(arg).operator str::u16string::base_type())
	{
		const wchar_t *j = TransliterateSymb(i);
		if (!j)
		{
			ret.push_back(i);
		}
		else
		{
			while (*j)
			{
				ret.push_back(*j++);
			}
		}
	}
	return str::u16string(ret);
}

void Openprovider::ProcessCommand()
{
	auto c_m_args = m_args.get();
	string cmd = c_m_args->Command.AsString();

	if (cmd == PROCESSING_CERTIFICATE_APPROVER)
	{
		try
		{
			std::cout << ApproverList(str::Int(c_m_args->Module), c_m_args->Domain, c_m_args->IntName).Str(true);
		}
		catch (...)
		{
			throw mgr_err::Error(PROCESSING_CERTIFICATE_APPROVER);
		}
	}
	else if (cmd == "dump_ssl_templates")
	{
		DumpSslTemplates(str::Int(c_m_args->Module));
	}
	else if (cmd == "get_contact_type")
	{
		std::cout << GetContactType(c_m_args->Tld.AsString()).Str(true);
	}
	else if (cmd == "update_ns")
	{
		UpdateNS(str::Int(c_m_args->Item));
	}
	else if (cmd == "import")
	{
		Import(str::Int(c_m_args->Module), c_m_args->ItemType, c_m_args->ImportSearchString);
	}
	else if (cmd == "transfer")
	{
		StringMap sm;
		Transfer(str::Int(c_m_args->Item), sm);
	}
}

void Openprovider::DumpSslTemplates(int module)
{
	SetModule(module);
	mgr_xml::Xml ret;
	auto templates = ret.SetRoot("templates");
	for (auto i : Remote_SslTemplates())
	{
		templates.AppendChild("template")
			.SetProp("name", "op_" + i.id)
			.SetProp("display_name", i.name)
			.SetProp("www", i.www ? "yes" : "no")
			.SetProp("idn", i.idn ? "yes" : "no")
			.SetProp("wildcard", i.wildcard ? "yes" : "no")
			.SetProp("multidomain", i.multidomain ? "yes" : "no")
			.SetProp("orginfo", i.orginfo ? "yes" : "no");
	}
	cout << ret.Str();
}

int Openprovider::GetMaxTryCount(const std::string &operation)
{
	if (operation == PROCESSING_PROLONG)
		return 1;
	return Module::GetMaxTryCount(operation);
}

void Openprovider::InternalAddItemParam(StringMap &params, const int iid)
{
	mgr_db::QueryPtr param = sbin::DB()->Query("SELECT pkey, csr, crt FROM certificate WHERE item = " + str::Str(iid));
	if (!param->Eof())
	{
		params["key"] = param->AsString("pkey");
		params["csr"] = param->AsString("csr");
		params["crt"] = param->AsString("crt");
	}
}

void Openprovider::SetParam(const int iid)
{
	sbin::ClientQuery("func=service.postsetparam&sok=ok&elid=" + str::Str(iid));
}

mgr_xml::Xml Openprovider::Remote_GetOpenxml()
{
	mgr_xml::Xml xml;
	auto root = xml.SetRoot("openXML");
	auto creds = root.AppendChild("credentials");
	creds.AppendChild("username", m_module_data["login"]);
	creds.AppendChild("password", m_module_data["password"]);
	return xml;
}

mgr_xml::Xml Openprovider::Remote_Send(mgr_xml::Xml req)
{
	string request = req.Str();
	LogExtInfo("Sending request:\n%s\n", request.c_str());

	mgr_rpc::HttpQuery http;
	http.AcceptAnyResponse();
	http.AddHeader("Content-Type: text/xml");
	
	std::stringstream ss;
	http.Post(m_module_data["url"], request, ss);
	
	mgr_xml::XmlString ret(ss.str());
	LogExtInfo("Response:\n%s\n", ss.str().c_str());

	auto reply = ret.GetNode("//reply");
	if (!reply)
	{
		throw mgr_err::Error("remote", "no_reply");
	}
	else if (reply.FindNode("code").Str() != "0")
	{
		string desc = reply.FindNode("desc").Str();
		if (auto data = reply.FindNode("data"))
		{
			desc += "\n" + data.Str();
		}
		throw mgr_err::Error("remote", "bad_code", desc);
	}
	return ret;
}

std::vector<SslTemplate> Openprovider::Remote_SslTemplates()
{
	std::vector<SslTemplate> ret;
	auto q = Remote_GetOpenxml();
	auto r = q.GetRoot().AppendChild("searchProductSslCertRequest");
	r.AppendChild("limit", "999");
	auto apiret = Remote_Send(q);
	for (auto i : apiret.GetNodes("//reply/data/results/array/item"))
	{
		SslTemplate cur;
		cur.id = i.FindNode("id").Str();
		cur.name = i.FindNode("brandName").Str() + " " + i.FindNode("name").Str();
		if (i.FindNode("isWildcardSupported").Str() == "1")
		{
			cur.wildcard = true;
		}
		if (true || i.FindNode("category").Str() == "organization_validation" ||
			i.FindNode("isExtendedValidationSupported").Str() == "1")
		{
			cur.orginfo = true;
		}
		if (i.FindNode("isIdnSupported").Str() == "1")
		{
			cur.idn = true;
		}
		if (str::Int(i.FindNode("numberOfDomains").Str()) > 1)
		{
			cur.multidomain = true;
		}
		ret.push_back(cur);
	}
	return ret;
}

StringVector Openprovider::Remote_SslApprovers(const string& domain, const string& cert)
{
	StringVector ret;
	auto q = Remote_GetOpenxml();
	auto r = q.GetRoot().AppendChild("retrieveApproverEmailListSslCertRequest");
	r.AppendChild("productId", cert);
	r.AppendChild("domain", domain);
	auto apiret = Remote_Send(q);
	for (auto i : apiret.GetNodes("//reply/data/array/item"))
	{
		ret.emplace_back(i.Str());
	}
	return ret;
}

namespace
{
	static void AddPhone(string phone, mgr_xml::XmlNode& r)
	{
		StringVector ret;
		if (!phone.size() || phone[0] != '+')
		{
			phone = "+" + phone;
		}
		str::inpl::Replace(phone, "(", "");
		str::inpl::Replace(phone, ")", "");
		str::inpl::Replace(phone, "-", "");
		str::Split(phone, ret, " ");
		if (ret.size() != 3)
		{
			ret.clear();
			str::inpl::Replace(phone, " ", "");
			ret.push_back(phone.substr(0, 2));
			ret.push_back(phone.substr(2, 3));
			ret.push_back(phone.substr(5));
		}

		auto &phoneList = ret;
		auto phoneNode = r.AppendChild("phone");
		phoneNode.AppendChild("countryCode", phoneList[0]);
		phoneNode.AppendChild("areaCode", phoneList[1]);
		phoneNode.AppendChild("subscriberNumber", phoneList[2]);
	}

	string CountryCode(const string& id)
	{
		return sbin::DB()->Query("SELECT iso2 FROM country WHERE id='" + id + "' LIMIT 1")->Str();
	}

	string CountryNameRu(const string& id)
	{
		return sbin::DB()->Query("SELECT name_ru FROM country WHERE id='" + id + "' LIMIT 1")->Str();
	}

	string CountryCodeRev(const string& code)
	{
		return sbin::DB()->Query("SELECT id FROM country WHERE iso2='" + code + "' LIMIT 1")->Str();
	}

	static void AddAddress(const string& address1, mgr_xml::XmlNode& address)
	{
		string address0 = address1, number;
		while (!address0.empty() && isdigit(*address0.rbegin()))
		{
			number = *address0.rbegin() + number;
			address0.resize(address0.size() - 1);
		}
		if (number.empty())
		{
			number = "1";
		}
		address.AppendChild("street", address0);
		address.AppendChild("number", number);
	}

	static void AddName(const string& fname, const string& lname, mgr_xml::XmlNode &r)
	{
		auto name = r.AppendChild("name");
		name.AppendChild("firstName", fname);
		name.AppendChild("lastName", lname);
		if (!fname.empty() && !lname.empty())
		{
			name.AppendChild("initials", fname[0] + string(".") + lname[0] + ".");
		}
		r.AppendChild("gender", "M");
	}

	static string GetDomainZoneCode(const string& domain)
	{
		string tld = domain, dom = str::GetWord(tld, '.');
		return sbin::DB()->Query("SELECT id FROM tld WHERE name='" + tld + "'")->Str();
	}
}

string Openprovider::Remote_CreateCertCustomer(const string& prefix)
{
	auto q = Remote_GetOpenxml();
	auto r = q.GetRoot().AppendChild("createCustomerRequest");
	r.AppendChild("companyName", params["org_name"]);
	auto address = r.AppendChild("address");
	address.AppendChild("country", CountryCode(params["org_country"]));
	address.AppendChild("state", params["org_state"]);
	address.AppendChild("city", params["org_city"]);
	address.AppendChild("zipcode", params["org_postcode"]);
	AddAddress(params["org_address"], address);
	AddName(params[prefix + "_fname"], params[prefix + "_lname"], r);
	AddPhone(params[prefix + "_phone"], r);
	r.AppendChild("email", params[prefix + "_email"]);
	auto apiret = Remote_Send(q);
	return apiret.GetNode("//reply/data/handle").Str();
}

string Openprovider::Remote_CreateCert(bool doReissue)
{
	auto q = Remote_GetOpenxml();
	auto r = q.GetRoot().AppendChild(doReissue ? "reissueSslCertRequest" : "createSslCertRequest");
	if (doReissue)
	{
		r.AppendChild("id", params[SERVICE_ORDER_ID]);
	}
	else
	{
		r.AppendChild("productId", pricelist.substr(3));
		r.AppendChild("period", str::Str(str::Int(params["period"]) / 12));
	}
	r.AppendChild("csr", params["csr"]);
	r.AppendChild("softwareId", "linux");
	StringVector sans;
	str::Split(params[CERTIFICATE_ALTNAME], sans, " ");
	if (!sans.empty())
	{
		auto hns = r.AppendChild("hostNames").AppendChild("array");
		for (auto i : sans)
		{
			hns.AppendChild("item", i);
		}
	}
	r.AppendChild("organizationHandle", params["adm_handle"]);
	r.AppendChild("technicalHandle", params["tech_handle"]);
	r.AppendChild("approverEmail", params["approver_email"]);
	r.AppendChild("signatureHashAlgorithm", "sha2");
	auto apiret = Remote_Send(q);
	return apiret.GetNode("//reply/data/id").Str();
}

Openprovider::OrderInfo Openprovider::Remote_GetCert(const string& id)
{
	auto q = Remote_GetOpenxml();
	auto r = q.GetRoot().AppendChild("retrieveOrderSslCertRequest");
	r.AppendChild("id", id);
	auto apiret = Remote_Send(q);
	auto data = apiret.GetNode("//reply/data");
	OrderInfo ret;
	ret.status = data.FindNode("status").Str();
	if (ret.status == "ACT")
	{
		string expire = data.FindNode("expirationDate").Str();
		ret.expire = str::GetWord(expire, ' ');
		ret.crt = data.FindNode("certificate").Str();
	}
	return ret;
}

Openprovider::OrderInfo Openprovider::Remote_GetDomain(const string& domainName)
{
	auto q = Remote_GetOpenxml();
	auto r = q.GetRoot().AppendChild("retrieveDomainRequest");
	auto domain = r.AppendChild("domain");
	string tld = domainName, dom = str::GetWord(tld, '.');
	domain.AppendChild("name", dom);
	domain.AppendChild("extension", tld);
	auto apiret = Remote_Send(q);
	auto data = apiret.GetNode("//reply/data");
	OrderInfo ret;
	ret.status = data.FindNode("status").Str();
	if (ret.status == "ACT")
	{
		string expire = data.FindNode("expirationDate").Str();
		ret.expire = str::GetWord(expire, ' ');
	}
	return ret;
}

string Openprovider::Remote_CreateDomainCustomer(const string& prefix)
{
	auto q = Remote_GetOpenxml();
	auto r = q.GetRoot().AppendChild("createCustomerRequest");
	if (params[prefix + "_company"] != "")
	{
		r.AppendChild("companyName", params[prefix + "_company"]);
	}
	auto address = r.AppendChild("address");
	address.AppendChild("country", CountryCode(params[prefix + "_postal_country"]));
	address.AppendChild("state", params[prefix + "_postal_state"]);
	address.AppendChild("city", params[prefix + "_postal_city"]);
	address.AppendChild("zipcode", params[prefix + "_postal_postcode"]);
	AddAddress(params[prefix + "_postal_address"], address);
	AddName(params[prefix + "_firstname"], params[prefix + "_lastname"], r);
	AddPhone(params[prefix + "_phone"], r);
	r.AppendChild("email", params[prefix + "_email"]);
	if (!params[prefix + "_birthdate"].empty() || !params[prefix + "_passport"].empty())
	{
		auto data = r.AppendChild("additionalData");
		data.AppendChild("birthDate", params[prefix + "_birthdate"]);
		data.AppendChild("passportNumber", params[prefix + "_passport"]);
	}
	auto extensionAdditionalData = r.AppendChild("extensionAdditionalData").AppendChild("array");
	for (auto i : { "ru", "su", "xn--p1ai" })
	{
		auto item = extensionAdditionalData.AppendChild("item");
		item.AppendChild("name", i);
		auto data = item.AppendChild("data");
		if (params[prefix + "_profiletype"] == "1")
		{
			data.AppendChild("firstNameCyrillic", params[prefix + "_firstname_locale_ru"]);
			data.AppendChild("middleNameCyrillic", params[prefix + "_middlename_locale_ru"]);
			data.AppendChild("lastNameCyrillic", params[prefix + "_lastname_locale_ru"]);
			data.AppendChild("firstNameLatin", params[prefix + "_firstname"]);
			data.AppendChild("middleNameLatin", params[prefix + "_middlename"]);
			data.AppendChild("lastNameLatin", params[prefix + "_lastname"]);
			data.AppendChild("passportSeries", params[prefix + "_passport_ru"].substr(0, 5));
			data.AppendChild("passportNumber", params[prefix + "_passport_ru"].substr(5));
			data.AppendChild("passportIssuer", params[prefix + "_passport_org_ru"]);
			data.AppendChild("passportIssueDate", params[prefix + "_passport_date"]);
			data.AppendChild("birthDate", params[prefix + "_birthdate"]);
		}
		else
		{
			data.AppendChild("сompanyNameCyrillic", params[prefix + "_company_locale_ru"]);
			data.AppendChild("сompanyNameLatin", params[prefix + "_company"]);
			data.AppendChild("taxPayerNumber", params[prefix + "_inn"]);
			data.AppendChild("postalAddressCyrillic", 
				CountryNameRu(params[prefix + "_postal_country"]) +
				" " + params[prefix + "_postal_postcode"] +
				" " + params[prefix + "_postal_state_ru"] +
				" " + params[prefix + "_postal_city_ru"] +
				" " + params[prefix + "_postal_address_ru"] +
				" " + params[prefix + "_postal_addressee_ru"]);
		}
		data.AppendChild("mobilePhoneNumber", params[prefix + "_phone"]);
		data.AppendChild("legalAddressCyrillic", 
			CountryNameRu(params[prefix + "_location_country"]) +
			" " + params[prefix + "_location_postcode"] +
			" " + params[prefix + "_location_state_ru"] +
			" " + params[prefix + "_location_city_ru"] +
			" " + params[prefix + "_location_address_ru"]);
	}
	auto apiret = Remote_Send(q);
	return apiret.GetNode("//reply/data/handle").Str();
}

void Openprovider::Remote_RenewDomain()
{
	StringVector ret;
	auto q = Remote_GetOpenxml();
	auto r = q.GetRoot().AppendChild("renewDomainRequest");
	auto domain = r.AppendChild("domain");
	string tld = params["domain"], dom;
	dom = str::GetWord(tld, '.');
	domain.AppendChild("name", dom);
	domain.AppendChild("extension", tld);
	r.AppendChild("period", str::Str(str::Int(params["period"]) / 12));
	Remote_Send(q);
}

void Openprovider::Remote_CreateDomain(const string& action)
{
	auto q = Remote_GetOpenxml();
	auto r = q.GetRoot().AppendChild((action + "DomainRequest").c_str());
	auto domain = r.AppendChild("domain");
	string tld = params["domain"], dom;
	dom = str::GetWord(tld, '.');
	domain.AppendChild("name", dom);
	domain.AppendChild("extension", tld);
	if (action == "transfer")
	{
		r.AppendChild("authCode", params["auth_code"]);
	}
	if (action == "transfer" || action == "create")
	{
		r.AppendChild("period", str::Str(str::Int(params["period"]) / 12));
		r.AppendChild("useDomicile", "1");
		r.AppendChild("autorenew", action == "transfer" ? "on" : "off");
	}
	for (auto i : DomainHandleTypes())
	{
		auto t = i;
		if (t == "bill") t = "billing";
		r.AppendChild((t + "Handle").c_str(), contact2handle[params[i + "_id"]]);
	}

	mgr_xml::XmlFile zonesConfig("etc/openprovider_tldconfig.xml");
	string idnScript, applicationMode;
	auto cfg = zonesConfig.GetNode("//tld[@pricelist='" + params["pricelist"] + "']");
	if (cfg)
	{
		idnScript = cfg.GetProp("idnscript");
		applicationMode = cfg.GetProp("applicationmode");
	}
	if (dom.substr(0, 4) == "xn--" && tld != "xn--p1ai")
	{
		if (idnScript != "")
		{
			//
		}
		else if (tld == "com" || tld == "net")
		{
			idnScript = "RUS";
		}
		else if (tld == "org")
		{
			idnScript = "RU";
		}
		else if (tld == "xn--80aswg" || tld == "xn--80asehdb")
		{
			idnScript = "Cyrl";
		}
		else if (tld == "xn--c1avg")
		{
			idnScript = "ru";
		}
		else
		{
			throw mgr_err::Value("idn_script");
		}
	}
	if (!idnScript.empty())
	{
		r.AppendChild("additionalData").AppendChild("idnScript", idnScript);
	}
	if (!applicationMode.empty())
	{
		r.AppendChild("applicationMode", applicationMode);
	}
	StringVector ns;
	for (int i = 0; i <= 4; ++i)
	{
		StringVector t;
		str::Split(params["ns" + str::Str(i)], " ", t);
		for (auto &i : t)
		{
			ns.emplace_back(i);
		}
	}
	if (ns.empty())
	{
		ns = { "ina1.registrar.eu", "ina2.registrar.eu", "ina3.registrar.eu" };
	}
	auto nservers = r.AppendChild("nameServers");
	auto array = nservers.AppendChild("array");
	for (auto i : ns)
	{
		auto item = array.AppendChild("item");
		StringVector parts;
		str::Split(i, "/", parts);
		if (parts.size() == 0)
		{
			continue;
		}
		item.AppendChild("name", parts[0]);
		if (parts.size() == 2)
		{
			item.AppendChild("ip", parts[1]);
		}
	}
	Remote_Send(q);
}

std::vector<Openprovider::DomainInfo> Openprovider::Remote_SearchDomain(int limit, int offset, const StringMap &params, int* total)
{
	auto q = Remote_GetOpenxml();
	auto r = q.GetRoot().AppendChild("searchDomainRequest");
	r.AppendChild("limit", str::Str(limit));
	r.AppendChild("offset", str::Str(offset));
	for (auto i : { "extension", "domainNamePattern", "contactHandle", "nsGroupPattern", "status" })
	{
		auto it = params.find(i);
		if (it != params.end())
			r.AppendChild(i, it->second);
	}
	auto apiret = Remote_Send(q);
	auto data = apiret.GetNode("//reply/data");
	if (total)
	{
		*total = str::Int(data.FindNode("total").Str());
	}

	std::vector<DomainInfo> ret;
	for (auto i : apiret.GetNodes("//reply/data/results/array/item"))
	{
		Debug("prep");
		DomainInfo cur;
		auto domNode = i.FindNode("domain");
		cur.domain = domNode.FindNode("name").Str() + "." + domNode.FindNode("extension").Str();
		Debug("dom %s", cur.domain.c_str());
		for (auto j : DomainHandleTypes())
		{
			Debug("Getting contact %s", j.c_str());
			string handle = i.FindNode((j == "bill" ? "billing" : j) + "Handle").Str();
			if (handle != "")
			{
				cur.handles[j] = handle;
			}
		}
		auto nsNode = i.FindNode("nameServers");

		if (nsNode)
		{
			auto arr = nsNode.FindNode("array");
			for (auto j = arr.FirstChild(); j; j = j.Next())
			{
				/* j = <item> */
				cur.ns.push_back(j.FindNode("name").Str());
			}
		}
		Debug("Getting exp");
		string exp = i.FindNode("expirationDate").Str();
		try
		{
			cur.expire = mgr_date::Date(str::GetWord(exp, ' '));
		}
		catch (mgr_err::Error&)
		{
			cur.expire = mgr_date::Date(static_cast<time_t>(0));
		}
		ret.push_back(cur);
		Debug("Got exp");
	}
	return ret;
}

mgr_xml::Xml Openprovider::Features()
{
	mgr_xml::Xml xml;
	auto itemtypes = xml.GetRoot().AppendChild("itemtypes");
	itemtypes.AppendChild("itemtype").SetProp("name", "certificate");
	itemtypes.AppendChild("itemtype").SetProp("name", "domain");
	auto params = xml.GetRoot().AppendChild("params");
	params.AppendChild("param").SetProp("name", "url");
	params.AppendChild("param").SetProp("name", "login");
	params.AppendChild("param").SetProp("name", "password").SetProp("crypted", "yes");
	auto features = xml.GetRoot().AppendChild("features");
	features.AppendChild("feature").SetProp("name", PROCESSING_CERTIFICATE_APPROVER);
	features.AppendChild("feature").SetProp("name", PROCESSING_PROLONG);
	features.AppendChild("feature").SetProp("name", PROCESSING_SYNC_ITEM);
	features.AppendChild("feature").SetProp("name", "transfer");
	features.AppendChild("feature").SetProp("name", "get_contact_type");
	features.AppendChild("feature").SetProp("name", "update_ns");
	features.AppendChild("feature").SetProp("name", "import");
	xml.GetRoot().AppendChild(mgr_xml::XmlFile("etc/openprovider_ssltemplates.xml").GetRoot());
	return xml;
}

void Openprovider::CheckParam(mgr_xml::Xml item_xml, const int item_id, const string& param_name, const string& value)
{
	Debug("check_param name=%s value=%s", param_name.c_str(), value.c_str());
	if (item_id)
	{
		Init(item_id);
	}
}

void Openprovider::Init(int iid)
{
	Debug("init id=%d", iid);
	auto item_query = ItemQuery(iid);
	for (size_t i = 0; i < item_query->ColCount(); ++i)
	{
		params[item_query->ColName(i)] = item_query->AsString(i);
	}
	itemtype = item_query->AsString("intname");
	pricelist = item_query->AsString("pricelist_intname");
	SetModule(item_query->AsInt("processingmodule"));
	AddItemParam(params, iid);
	AddItemAddon(params, iid, item_query->AsInt("pricelist"));
	if (itemtype == "certificate")
	{
		/*ForEachI(mgr_crypto::x509::DecodeRequest(params["csr"]).GetSubject(), s)
		{
			params[s->first] = s->second;
		}*/
	}
	else if (itemtype == "domain")
	{
		ForEachQuery(sbin::DB(),
			"SELECT sp2i.type, sp2i.service_profile, externalid, sp.profiletype "
			"FROM service_profile2item sp2i "
			"LEFT JOIN service_profile2processingmodule sp2pm "
			"ON sp2pm.service_profile = sp2i.service_profile "
			"AND sp2pm.processingmodule = " + params["processingmodule"] + " " 
			" JOIN service_profile sp ON sp.id = sp2i.service_profile "
			"WHERE item = " + str::Str(iid), i)
		{
			ForEachQuery(sbin::DB(),"SELECT intname, value FROM service_profileparam WHERE service_profile=" + i->AsString(1), j)
			{
				params[i->AsString(0) + "_" + j->AsString(0)] = Transliterate(j->AsString(1));
				params[i->AsString(0) + "_" + j->AsString(0) + "_ru"] = j->AsString(1);
			}
			contact2handle[i->AsString(1)] = i->AsString(2);
			//params[i->AsString(0) + "_handle"] = i->AsString(2);
			params[i->AsString(0) + "_id"] = i->AsString(1);
			params[i->AsString(0) + "_profiletype"] = i->AsString(3);
		}
	}
}

void Openprovider::Open(int iid)
{
	Init(iid);
	Debug("type %s", itemtype.c_str());
	if (itemtype == "certificate")
	{
		params["adm_handle"] = Remote_CreateCertCustomer("adm");
		SaveParam(iid, "adm_handle", params["adm_handle"]);
		params["tech_handle"] = Remote_CreateCertCustomer("tech");
		SaveParam(iid, "tech_handle", params["tech_handle"]);
		params[SERVICE_ORDER_ID] = Remote_CreateCert();
		SaveParam(iid, SERVICE_ORDER_ID, params[SERVICE_ORDER_ID]);
		SetServiceStatus(iid, 3 /* Cert is requested */);
		sbin::ClientQuery("func=service.postopen&sok=ok&elid=" + str::Str(iid));
	}
	else if (itemtype == "domain")
	{
		RegisterDomainContacts();
		Remote_CreateDomain("create");
		SyncItem(iid);
		sbin::ClientQuery("func=service.postopen&sok=ok&elid=" + str::Str(iid));
	}
}

void Openprovider::Prolong(int iid)
{
	Init(iid);
	if (itemtype == "certificate")
	{
		Open(iid);
	}
	else if (itemtype == "domain")
	{
		Remote_RenewDomain();
	}
	sbin::ClientQuery("func=service.postprolong&sok=ok&elid=" + str::Str(iid));
}

void Openprovider::Reopen(int iid)
{
	Init(iid);
	if (itemtype == "certificate")
	{
		Remote_CreateCert(true);
		SetServiceStatus(iid, 3 /* Cert is requested */);
	}
}

void Openprovider::Resume(int iid)
{
	sbin::ClientQuery("func=service.postresume&sok=ok&elid=" + str::Str(iid));
}

void Openprovider::Suspend(int iid)
{
	sbin::ClientQuery("func=service.postsuspend&sok=ok&elid=" + str::Str(iid));
}

void Openprovider::Close(int iid)
{
	sbin::ClientQuery("func=service.postclose&sok=ok&elid=" + str::Str(iid));
}

mgr_xml::Xml Openprovider::ApproverList(const int mid, const string& domain, const string& intname)
{
	SetModule(mid);
	mgr_xml::Xml approver;
	auto node = approver.GetRoot().AppendChild("domain").SetProp("name", domain);
	for (auto i : Remote_SslApprovers(domain, intname.substr(3)))
	{
		node.AppendChild("approver", i);
	}
	return approver;
}

void Openprovider::SyncItem(int iid)
{
	Init(iid);
	if (itemtype == "certificate")
	{
		auto crt = Remote_GetCert(params[SERVICE_ORDER_ID]);
		if (crt.status == "ACT")
		{
			if (params[SERVICE_STATUS] != str::Str(5))
			{
				sbin::ClientQuery("func=certificate.save&elid=" + str::Str(iid) + "&crt=" + str::url::Encode(crt.crt));
				sbin::ClientQuery("func=certificate.open&sok=ok&elid=" + str::Str(iid));
				SetServiceStatus(iid, 5 /* ssl_util::isIssued */);
				SetServiceExpireDate(iid, crt.expire);
			}
		}
	}
	else if (itemtype == "domain")
	{
		auto dom = Remote_GetDomain(params["domain"]);
		if (dom.status == "ACT")
		{
			if (params[SERVICE_STATUS] != str::Str(2))
			{
				sbin::ClientQuery("func=domain.open&sok=ok&service_status=2&elid=" + str::Str(iid));
				SetServiceExpireDate(iid, dom.expire);
			}
		}
	}
}

mgr_xml::Xml Openprovider::GetContactType(const string& tld)
{
	static std::set<string> ru_tld{"ru", "su", "рф", "xn--p1ai", "com.ru", "net.ru", "pp.ru"};
	string type = ru_tld.count(tld) ? "default" : "global";
	mgr_xml::Xml xml;
	xml.GetRoot().SetProp("auth_code", "require").SetProp("ns", "require");
	for (auto i : DomainHandleTypes())
	{
		xml.GetRoot().AppendChild("contact_type", i).SetProp("type", type);
	}
	return xml;
}

void Openprovider::RegisterDomainContacts()
{
	for (auto i : DomainHandleTypes())
	{
		string id = params[i + "_id"];
		if (contact2handle[id] == "")
		{
			contact2handle[id] = Remote_CreateDomainCustomer(i);
			sbin::ClientQuery("func=service_profile2processingmodule.edit"
				"&sok=ok"
				"&service_profile=" + id +
				"&processingmodule=" + params["processingmodule"] +
				"&externalid=" + contact2handle[id] +
				"&type=owner");
		}
	}
}

void Openprovider::UpdateNS(int iid)
{
	Init(iid);
	Remote_CreateDomain("modify");
}

void Openprovider::Import(const int mid, const string& itemtype, const string& search)
{
	auto db = sbin::DB();

	SetModule(mid);
	
	params["processingmodule"] = str::Str(mid);

	if (itemtype != "domain")
	{
		throw mgr_err::Error("unsupported", "itemtype");
	}
	StringMap filterParams;
//	str::Split(search, ";", filterParams);
	if (search != "")
	{
		string tld = search, dom;
		dom = str::GetWord(tld, '.');
		filterParams["extension"] = tld;
		filterParams["domainNamePattern"] = dom;
	}
	int current = 0;
	int total = 1;
	int LIMIT = 100;

	StringMap handle2contact;

	while (current < total)
	{
		auto ret = Remote_SearchDomain(LIMIT, current, filterParams, &total);
		current += LIMIT;

		for (auto &i : ret)
		{
			StringMap domainParams;
			domainParams["module"] = params["processingmodule"];
			domainParams["import_itemtype_intname"] = "domain";
			domainParams["import_pricelist_intname"] = GetDomainZoneCode(i.domain);
			domainParams["import_service_name"] = i.domain;
			domainParams["status"] = "2";
			domainParams["expiredate"] = i.expire.operator string();
			domainParams["domain"] = i.domain;
			domainParams["service_status"] = "2";
			domainParams["period"] = "12";
			domainParams["sok"] = "ok";
			for (auto &j : i.handles)
			{
				if (handle2contact[j.second] == "")
				{
					auto q = db->Query("SELECT service_profile "
						"FROM service_profile2processingmodule "
						"WHERE processingmodule = " + params["processingmodule"] + " " +
						"AND externalid=" + db->EscapeValue(j.second));

					if (q->First())
					{
						handle2contact[j.second] = q->AsString(0);
					}
					else
					{
						handle2contact[j.second] = StoreContact(j.second);
					}
				}
				domainParams[j.first] = handle2contact[j.second];
			}
			int nsIdx = 0;
			for (auto &j : i.ns)
			{
				domainParams["ns" + str::Str(nsIdx++)] = j;
			}
			string elid = sbin::ClientQuery("processing.import.service", domainParams).value("service_id");
			for (auto &j : i.handles)
			{
				sbin::ClientQuery("service_profile2item.edit", {
					{"sok", "ok"},
					{"item", elid},
					{"service_profile", handle2contact[j.second]},
					{"type", j.first}
				});
			}
		}
	}
}

string Openprovider::StoreContact(const string& extid)
{
	auto q = Remote_GetOpenxml();
	auto r = q.GetRoot().AppendChild("retrieveCustomerRequest");
	r.AppendChild("handle", extid);
	r.AppendChild("withAdditionalData", "true");
	auto apiret = Remote_Send(q);
	auto data = apiret.GetNode("//reply/data");
	auto ad = data.FindNode("additionalData");
	StringMap contactParams;
	contactParams["module"] = params["processingmodule"];
	contactParams["type"] = "owner";
	contactParams["sok"] = "ok";
	contactParams["externalid"] = extid;
	contactParams["birthDate"] = Get(ad, "birthDate");
	contactParams["email"] = Get(data, "email");
	contactParams["fax"] = Get(data, "fax");
	contactParams["firstname"] = Get(data.FindNode("name"), "firstName");
	contactParams["lastname"] = Get(data.FindNode("name"), "lastName");
	auto address = data.FindNode("address");
	contactParams["location_address"] = Get(address, "street") + " " + Get(address, "number");
	contactParams["location_city"] = Get(address, "city");
	contactParams["location_country"] = CountryCodeRev(Get(address, "country"));
	contactParams["location_postcode"] = Get(address, "zipcode");
	contactParams["location_state"] = Get(address, "state");
	contactParams["passport"] = Get(ad, "passportNumber");
	contactParams["phone"] = Get(data, "phone");
	contactParams["profiletype"] = "1";
	contactParams["name"] = contactParams["firstname"] + " " + contactParams["lastname"] + " (" + extid + ")";
	auto ret = sbin::ClientQuery("processing.import.profile", contactParams);
	return ret.value("profile_id");
}

void Openprovider::Transfer(int iid, StringMap&)
{
	Init(iid);
	RegisterDomainContacts();
	Remote_CreateDomain("transfer");
	SyncItem(iid);
	sbin::ClientQuery("func=service.postopen&sok=ok&elid=" + str::Str(iid));
}

RUN_MODULE(processing::Openprovider)
