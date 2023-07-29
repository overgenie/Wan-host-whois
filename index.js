const express = require("express")
const app = express()
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const whoiser = require('whoiser')
const axios = require('axios');
app.set('view engine', 'ejs');
app.use('/assets', express.static('public'))

var server = "http://localhost:8000" //WARNING : IT IS REQUIRED TO UPDATE THIS SERVER VALUE DEPENDING WHERE THE SERVER IS HOSTED

app.get("/api/whois", async (req, res) => {
  var domain = req.query.domain
  const domains_list = require("./domains.json")
  if(!req.query.domain || req.query.domain.split(".").length < 2 || !domains_list.includes(domain.split('.')[domain.split('.').length - 1].toUpperCase())) return res.status(401).json({"message": "Non-Authoritative Information", "code": 204})

    var domain_array = domain.split('.')
    const data = await whoiser.domain(domain_array[domain_array.length - 2]+'.'+domain_array[domain_array.length - 1])

    var tld = await whoiser(`.${domain_array[domain_array.length - 1]}`)
    tld = tld["whois"]

    const formated_data = {
      "name servers": data[tld]["Name Server"],
      "domain name": data[tld]["Domain Name"],
      "Registry Domain ID": data[tld]["Registry Domain ID"],
      "Registrar WHOIS Server": data[tld]["Registrar WHOIS Server"],
      "Registrar URL": data[tld]["Registrar URL"],
      "Updated Date": data[tld]["Updated Date"],
      "Created Date": data[tld]["Created Date"],
      "Expiry Date": data[tld]["Expiry Date"],
      "Registrar": data[tld]["Registrar"],
      "Registrar IANA ID": data[tld]["Registrar IANA ID"],
      "Registrar Abuse Contact Email": data[tld]["Registrar Abuse Contact Email"],
      "Registrar Abuse Contact Phone": data[tld]["Registrar Abuse Contact Phone"],
      "DNSSEC": data[tld]["DNSSEC"],
    }
    res.status(200).json(formated_data)
  
  
})

app.get("/search", async (req, res) => {
  if(!req.query.q) return res.redirect("/")
  else return res.redirect("/search/"+req.query.q)
  //const data = await fetch("/api/whois?domain="+req.query.q).then(res => res.json())

  //console.log(data)

})

app.get("/search/:domain", async (req, res) => {
  try{

    const data = await fetch(server+"/api/whois?domain="+req.params.domain).then(resp => resp.json())
    const status = await fetch(server+"/api/whois?domain="+req.params.domain).then(resp => resp.status)

    console.log(status)

    if(status != 200) return res.status(401).redirect("/")

    else res.render("search.ejs", {
      data: data
    })

  } catch (error) {
    console.error(error);
  }
})

app.get("/", (req, res) => {
  res.render("index.ejs")
})


app.listen(8000, () => console.log("app running !"))
