
import express from  "express";
import { MongoClient } from "mongodb";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import  nodemailer  from "nodemailer";
import otpGenerator from 'otp-generator';
import  shortid from 'shortid';
import * as dotenv from 'dotenv' // see https://github.com/motdotla/dotenv#how-do-i-use-dotenv-with-impo
import { url } from "inspector";
dotenv.config()
const app = express();
const PORT = process.env.PORT;
app.use(cors())
app.use(express.json());
// const MONGO_URL = "mongodb://127.0.0.1";
const MONGO_URL = process.env.MONGO_URL;
const client = new MongoClient(MONGO_URL); 
// Top level awai
await client.connect(); // call
console.log("Mongo is connected !!!  ");
async function generateHashedpassword(password){
  const NO_OF_ROUNDS = 10;
  const salt = await bcrypt.genSalt(NO_OF_ROUNDS)
  const passwordHash = await bcrypt.hash(password, salt)
    return passwordHash

}
app.get("/", function (request, response) {
  response.send("🙋‍♂️, 🌏 🎊✨🤩");
});
app.get("/url/:url", async function (request, response) {
  const url = request.params.url
  const find2 = await client .db("day-44").collection("urldata").findOne({converted_url:url });
  response.redirect(find2.original_url)
});
app.post("/Signup", async function (request, response) {
    const ddd = request.body;
  
    const userCheck = await client
      .db("day-44")
      .collection("userdata")
      .findOne({ username: ddd.username });
    if (userCheck) {
      response.status(400).send({ message: "username already exists" });
    } else if (ddd.password.length < 8) {
      response
        .status(400)
        .send({ message: "password must be at least 8 characters" });
    } else {
      const pass = ddd.password;
      const password_hash = await generateHashedpassword(pass);
      const usertoken2 = jwt.sign({ username: ddd.username }, process.env.SECRET_KEY);
      const da = {
        username: ddd.username,
        password: password_hash,
        usertoken: usertoken2,
        email: ddd.email,
        URL_POST :[],

      };
      const post = await client.db("day-44").collection("userdata").insertOne(da);
      const userCheck2 = await client
        .db("day-44")
        .collection("userdata")
        .findOne({ username: ddd.username });
      const token = jwt.sign({ id: userCheck2._id }, process.env.SECRET_KEY);
      // console.log("token: " + token);
      response.send({ user_id: userCheck2.usertoken, token: token })
    }
  });
app.put("/Forgetpassword", async function (request, response) {
    const { username, Newpassword ,email} = request.body;
    console.log("email",email)
    const userCheck = await client.db("day-44").collection("userdata").findOne({ username: username });
      if(!userCheck){
        response.status(400).send({ message: "invalid credentials" });
      }else{
      

        const token = jwt.sign({ id: userCheck._id }, process.env.SECRET_KEY);
        response.send({ user_id: userCheck.usertoken, token: token });
        const mailsend = nodemailer.createTransport({
            service : "gmail",
            auth : {
                user : process.env.EMAIL,
                pass : process.env.PASSWORD
            }
        })
        const otp = otpGenerator.generate(6, { upperCaseAlphabets: false, specialChars: false ,digits : true})
       
        const composeMail = {
            from: process.env.EMAIL,
            to: email,
            subject: "OTP for Reset Password",
            text: `OTP Number : ${otp}`,
          };
            const otpset = await client.db("day-44").collection("userdata").updateOne({ usertoken :userCheck.usertoken },{$set:{OTP : otp}});
        console.log(otpset)
          mailsend.sendMail(composeMail, (error, info) => {
            if (error) {
              console.log(error);
            } else {
              console.log(`Email ${info.response}`);
            }
          });


                    
      }
    
  });
app.post("/Login", async function (request, response) {
    const { username, password } = request.body;
    const userCheck = await client.db("day-44").collection("userdata").findOne({ username: username });
      if(!userCheck){
        response.status(400).send({ message: "invalid credentials" });
      }else{
        const comparepassword = await bcrypt.compare(password, userCheck.password);
      if (comparepassword) {
        const token = jwt.sign({ id: userCheck._id }, process.env.SECRET_KEY);
        response.send({ user_id: userCheck.usertoken, token: token });
      } else {
        response.status(400).send({ message: "invalid credentials" });
      }
      }
    
  });
app.post("/Profile/:usertoken", async function (request, response) {
       
    const userCheck = await client.db("day-44").collection("userdata").findOne({ usertoken : request.params.usertoken });
     response.send(userCheck)
  });
app.put("/Addurlpost/:usertoken", async function (request, response) {

    const data = request.body
    const {usertoken  } = request.params;
    const date = new Date()
    const orignal = {
        Date:date.toLocaleDateString(),
        original_url : data.url,
        converted_url : shortid.generate(data.url)
    }
  //  console.log(orignal)
    const userCheck = await client .db("day-44").collection("userdata").updateOne({  usertoken: usertoken },{ $push:{URL_POST : orignal}});
    const userCheck2 = await client .db("day-44").collection("urldata").insertOne(orignal);
     response.send(userCheck) 
    //  console.log(userCheck)
  });
app.listen(PORT, () => console.log(`The server started in: ${PORT} ✨✨`));
