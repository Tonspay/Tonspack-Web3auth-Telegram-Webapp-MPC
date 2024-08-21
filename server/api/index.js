const jwt = require("jsonwebtoken");
const fs = require("fs");
const express = require("express");
const dotenv = require("dotenv");
const crypto = require("crypto");
const path = require("path");
const { AuthDataValidator } = require("@telegram-auth/server");
const { objectToAuthDataMap } = require("@telegram-auth/server/utils");

dotenv.config();

const app = express();

const { TELEGRAM_BOT_NAME, TELEGRAM_BOT_TOKEN, SERVER_URL, CLIENT_URL, JWT_KEY_ID } = process.env;
const TELEGRAM_BOT_CALLBACK = `${SERVER_URL}/callback`;
const privateKey = fs.readFileSync(path.resolve(__dirname, "privateKey.pem"), "utf8");

// A helper function to generate JWT token using the Telegram user data
const generateJwtToken = (userData) => {
  const payload = {
    telegram_id: userData.id,
    username: userData.username,
    avatar_url: userData.photo_url,
    sub: userData.id.toString(),
    name: userData.first_name,
    iss: "https://api.telegram.org",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 60 * 60, // 1 hour expiration
  };

  return jwt.sign(payload, privateKey, { algorithm: "RS256", keyid: JWT_KEY_ID });
};

app.get("/", (req, res) => res.send("Express on Vercel for Telegram Login to be used with Web3Auth"));

app.get("/.well-known/jwks.json", (req, res) => {
  const jwks = fs.readFileSync(path.resolve(__dirname, "jwks.json"), "utf8");
  res.send(JSON.parse(jwks));
});

// Endpoint to serve the login page
app.get("/login", (req, res) => {
  let htmlContent = `
  <!DOCTYPE html>
  <html lang="en">
    <head>
      <title>Telegram OAuth App with Web3Auth</title>
      <style>
        body {
          display: flex;
          justify-content: center;
          align-items: center;
          height: 100vh;
          margin: 0;
        }
      </style>
    </head>
    <body>
      <script>
        const script = document.createElement("script");
        script.async = true;
        script.src = "https://telegram.org/js/telegram-widget.js?22";
        script.setAttribute("data-telegram-login", "${TELEGRAM_BOT_NAME}");
        script.setAttribute("data-size", "large");
        script.setAttribute("data-userpic", "false");
        script.setAttribute("data-auth-url", "${SERVER_URL}/callback");

        document.body.appendChild(script);
      </script>
      <noscript>You need to enable JavaScript to run this app.</noscript>
    </body>
  </html>
  `;

  res.send(htmlContent);
});


app.get("/try", (req, res) => {
  let htmlContent = `
  <!DOCTYPE HTML>
  <html lang="en">
  
  <head>
  
      <title>Tonspack Webapp Auth</title>
  
      <meta id="theme-check" name="theme-color" content="#FFFFFF">
  
      <body onload="init()">
  
          <div id='content'>
  
          </div>
          <!-- Telegram -->
          <script src="https://bundle.run/buffer@6.0.3"></script>
          <script type="text/javascript">
            window.Buffer = window.Buffer ?? buffer.Buffer;
          </script>
          <script src="https://telegram.org/js/telegram-web-app.js"></script>
          <script src="https://unpkg.com/@tonconnect/sdk@latest/dist/tonconnect-sdk.min.js"></script>
          <script>
              
              async function miniapp_init() {
                  await Telegram.WebApp.ready();
                  if (window.Telegram.WebApp.initData) {
                      return window.Telegram.WebApp.initData
                  }
                  return false
              }
  
              async function init()
              {
                  const data = await miniapp_init()
                  console.log(
                      data
                  )
                  const bs64 = Buffer.from(data).toString("base64")
                  const redirect =  location.origin + '/do?auth='+bs64
                  console.log("🔥",redirect)
                  location.href = redirect
  
              }
          </script>
      </body>
  </head>
  
  </html>
  `;

  res.send(htmlContent);
});
// Endpoint to handle the Telegram callback
app.get("/do", async (req, res) => {

  const rawData = Buffer.from(req.query.auth,"base64").toString("utf-8")

  console.log(rawData)

  const data = Object.fromEntries(new URLSearchParams( rawData ));

  const udata = JSON.parse(data.user)

  data['user']=udata

  console.log(data)
  verify = tgVerfiy(TELEGRAM_BOT_TOKEN,rawData)

  console.log(verify,TELEGRAM_BOT_TOKEN)
  if(verify)
  {
    console.log(udata)

    const JWTtoken = generateJwtToken(udata);
    console.log(
      "🔥 JWTtoken",JWTtoken
    )


    const redirectUrl = `${CLIENT_URL}?token=${JWTtoken}`; // Redirect back to frontend with token
    console.log(
      "🔥 redirectUrl",redirectUrl
    )

    res.redirect(redirectUrl);
  }else{
    res.status(200).send({
      "code": 200,
      "data": "lol"
  })
  }

})
app.get("/test/callback", async (req, res) => {
  const validator = new AuthDataValidator({ botToken: TELEGRAM_BOT_TOKEN });
  console.log(
    "🔥 validator",validator
  )

  const data = objectToAuthDataMap(req.query || {});
  console.log(
    "🔥 data",data
  )


  try {
    const user = await validator.validate(data);
    console.log(
      "🔥 user",user
    )

    const JWTtoken = generateJwtToken(user);
    console.log(
      "🔥 JWTtoken",JWTtoken
    )


    const redirectUrl = `${CLIENT_URL}?token=${JWTtoken}`; // Redirect back to frontend with token
    console.log(
      "🔥 redirectUrl",redirectUrl
    )

    res.redirect(redirectUrl);


  } catch (error) {
    console.error("Error validating Telegram data:", error);
    res.status(400).send("Invalid Telegram data");
  }
});

function tgVerfiy(apiToken, telegramInitData) {
  const initData = new URLSearchParams(telegramInitData);
  
  console.log(initData)
  initData.sort();

  const hash = initData.get("hash");
  initData.delete("hash");

  const dataToCheck = [...initData.entries()].map(([key, value]) => key + "=" + value).join("\n");

  const secretKey = crypto.createHmac("sha256", "WebAppData").update(apiToken).digest();

  const _hash = crypto.createHmac("sha256", secretKey).update(dataToCheck).digest("hex");

  return hash === _hash;
}


app.listen(3000, () => console.log("Server ready on port 3000."));

module.exports = app;