require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const { accessSync, appendFile } = require('fs');
const mongoose = require('mongoose');
const todoSchema = require('./models/todo');
const userSchema = require('./models/user');
const { log, error } = require('console');
const { config, listeners } = require('process');
const sendMail = require('./middlewares/sendMail');
const sendRecoveryMail = require('./middlewares/sendMail2');
const flash = require('express-flash');
const bodyParser = require('body-parser');
const session = require('express-session');
const app = express();
const port = process.env.PORT || 3000;
const secretKey = process.env.JWT_SECRET;

app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: true,
}));
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!'); // You can customize this response
});
app.use(flash());
app.set('view engine', 'ejs');
app.use(express.json());
app.use(bodyParser.json()); // Parse JSON bodies
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

//Middlewares
// async function tokenChecker(req,res,next) {
//   let token = jwt.verify(req.cookies.token,secretKey)
//   let {email} = token
//   const {sessions} = await userSchema.findOne({email})
//   if(!sessions && !req.cookies.token){
//     pass
//   }
// }
async function isLoggedIn(req, res, next) {
  try{

    if (!req.cookies.token){
      res.redirect('/signup');
    } else {
      let decoded = jwt.verify(req.cookies.token, secretKey);
      let Usertoken = await userSchema.findOne({email:decoded.email})
      if(await Usertoken.sessions.indexOf(req.cookies.token) == -1){
        res.clearCookie("token")
        res.redirect('/signup')
      }
      else{
        req.user = decoded;
        next();
      }
    }
  }
  catch{
    req.flash('message',"Something Broked!")
    res.redirect('/auth')
  }
}
async function isSessionVaid(req,res,next){
  try{
    let {email} = jwt.verify(req.cookies.token,secretKey);
    let user = await userSchema.findOne({email});
    if (!user.sessions.includes(req.cookies.token)){
      res.cookie("token","")
      next()
    } 
    else{
      console.log('No token present')
      next()
    }
  }
  catch{
    console.log("err")
    next()
  }

}
function isNotLoggedIn(req,res,next) {
  if (!req.cookies.token) {
    next();
  } else {
    req.flash('message','You must Log Out inorder to signin.');
    return res.redirect('/auth');
  }
}
async function isSessionOverLimit(email,res,req){
  let user = await userSchema.findOne({email});
  if(user){
    const {sessions} = user;
    if(sessions.length >= 5 ){
      req.flash('message', 'Please log out from other devices. A maximum of 5 devices can be logged in simultaneously.');
      res.redirect('/auth');
    }
    else{
      return 0;
    }
  }
  else{
    return 0;
  }
}
function genOTP() {
  return (Math.floor(1000 + Math.random() * 9000)).toString();
}
function deviceIp() {
  let data = fetch('http://ip-api.com/json?field=61439')
  .then(response => response.json())

  return data
}
function detectDevice(userAgent){
  let data = fetch(`https://api.apicagent.com/?ua=${userAgent}`)
  .then(res => res.json())

  return data
  
}
const blacklist = new Set();

function invalidateToken(token) {
  blacklist.add(token);
}


app.get('/',isSessionVaid, async(req, res) => {
  let token = req.cookies.token;
  res.render('home', { token });
});

app.get('/signup',isNotLoggedIn, (req, res) => {
  let msg;
  try {
    msg = req.flash('message')
  } catch {
    msg = null
  }
  let token = req.cookies.token;
  res.render('signup', { token, msg });
});

app.post('/signup', async (req, res) => {
  try{

    const { username, email, password } = req.body;
  
    console.log("H")
    let uniqueUser = await userSchema.findOne({ email });
    if (!uniqueUser) {
      console.log("H")
      let otp = genOTP();
      console.log("H")
      console.log(otp);
      sendMail(email, otp);
      let code = jwt.sign({ otp, email, password, username }, secretKey);
      res.cookie("code", code)
      req.flash('email-message',`Enter the OTP recieved at ${email}`)
    }
    else {
      req.flash('message', "User already exists.")
      res.redirect('/signup')
    }
    res.redirect('/email');
  }
  catch{
    req.flash('message',"Something broked!")
    res.redirect('/auth')
  }
});

app.get('/email', (req, res) => {
  let msg;
  try {
    msg = req.flash('message')
  } catch {
    msg = null
  }
  console.log(msg)
  res.render('email', { msg });
});

app.post('/email/verify', async(req, res) => {
  const userAgent = req.headers['user-agent'];
  const myDeviceData = await deviceIp()
  const myDevice = await detectDevice(userAgent)

  let { code_1, code_2, code_3, code_4 } = req.body;
  let otp = (code_1 + code_2 + code_3 + code_4).toString();
  let code = jwt.verify(req.cookies.code, secretKey);
  console.log("HJI",code)
  if (otp == code.otp) {
    bcrypt.genSalt(10, (err, salt) => {
      const { email, username, password } = jwt.verify(req.cookies.code, secretKey);
      bcrypt.hash(password, salt, async (err, hash) => {
        let token = jwt.sign({ email ,  myDeviceData, myDevice }, secretKey);

        let user = await userSchema.create({ 
          username: username,
          email: email, 
          password: hash, 
          date:new Date().toISOString().slice(0, 10),
        });
        user.sessions.push(token);
        await user.save();

        res.clearCookie('code', { path: '/' });
        res.cookie("token", token);
        res.redirect('/todo');
      });
    });
  } else {
    req.flash('message', "Incorrect OTP.");
    res.redirect('/email');
  }
});

app.get('/signin',isNotLoggedIn, (req, res) => {
  let msg;
  try {
    msg = req.flash('message');
  } catch {
    msg = null
  }
  let token = req.cookies.token;
  res.render('signin', { token, msg });
});

app.post('/signin', async (req, res) => {
  let { email, password } = req.body;
  await isSessionOverLimit(email,res,req);
  const userAgent = req.headers['user-agent'];
  const myDeviceData = await deviceIp();
  const myDevice = await detectDevice(userAgent);
  
  let user = await userSchema.findOne({ email });
  console.log(user)
  if (user) {
    bcrypt.compare(password, user.password, async(err, result) => {
      if (result) {
        let token = jwt.sign({ email , myDeviceData , myDevice }, secretKey);
        res.cookie("token", token);
        await userSchema.updateOne({email},{ $push: {sessions:token}});
        res.redirect('/todo');
      } else {
        req.flash('message', "Forgot Password?");
        res.redirect('/signin');
      }
    });
  } else {
    console.log('Hi7')
    req.flash('message', "Email or password is incorrect.")
    res.redirect('/signin');
  }
});
app.get('/todo', isLoggedIn, async (req, res) => {
  let token = jwt.verify(req.cookies.token, secretKey);
  let todo = await todoSchema.find({ email: token.email });
  res.render('todo', { token, todo });
});

app.post('/todo', isLoggedIn, async (req, res) => {
  let clicked = req.body.clicked;
  let email = req.user.email;
  if (clicked >= 0) {
    let AllTodos = await todoSchema.find({ email });
    for (let index = 0; index < AllTodos.length; index++) {
      if (index == clicked) {
        let clickedTodo = AllTodos[index];
        let todo = await todoSchema.findOne({ _id: clickedTodo._id });
        todo.checked = !todo.checked;
        await todo.save();
        break;
      }
    }
  }
});

app.post('/todo/create', (req, res) => {
  let token = req.cookies.token;
  let { title } = req.body;
  let Tododetails = null;
  res.render('maketodo', { Tododetails, token, title });
});

app.post('/todo/create/save', isLoggedIn, async (req, res) => {
  let { title, desc, date_startline, time_startline, date_deadline, time_deadline } = req.body;
  let email = req.user.email;
  let todo = await todoSchema.create({
    email: email,
    title: title,
    desc: desc,
    timeStart: time_startline,
    timeDead: time_deadline,
    dateStart: date_startline,
    dateDead: date_deadline,
    checked: false
  });
  let user = await userSchema.findOne({ email })
  user.todos.push(todo._id)
  await user.save();
  res.redirect('/todo');
});

app.get('/logout',isLoggedIn, async(req, res) => {
  if(req.cookies.token){
    const {email} = req.user;
    await userSchema.updateOne({email},{ $pull: {sessions:req.cookies.token}});
    res.clearCookie("token");
    res.redirect('/');
  }
});


app.get('/edit/:clicked', isLoggedIn, async (req, res) => {
  const email = req.user.email;
  const clicked = req.params.clicked;
  const token = req.cookies.token;
  const allTodos = await todoSchema.find({ email });
  let todo = await allTodos[clicked];
  let Tododetails = {
    title: todo.title,
    desc: todo.desc,
    timeStart: todo.timeStart,
    timeDead: todo.timeDead,
    dateStart: todo.dateStart,
    dateDead: todo.dateDead,
    id: todo._id
  };
  res.render('maketodo', { Tododetails, token });
});

app.post('/todo/edit/save/:id', isLoggedIn, async (req, res) => {
  const email = req.user.email;
  const id = req.params.id;
  const { title, desc, date_startline, time_startline, date_deadline, time_deadline } = req.body;
  let allTodos = await todoSchema.findOneAndUpdate({ _id: id }, {
    title: title,
    desc: desc,
    timeStart: time_startline,
    timeDead: time_deadline,
    dateStart: date_startline,
    dateDead: date_deadline,
  });
  await allTodos.save();
  res.redirect('/todo');
});

app.get('/delete/:clicked', isLoggedIn, async (req, res) => {
  const clicked = req.params.clicked;
  const email = req.user.email;
  const allTodos = await todoSchema.find({ email });
  let todo = allTodos[clicked];
  await todoSchema.deleteOne({ _id: todo._id });
  res.redirect('/todo');
});

app.get('/forgot', (req, res) => {
  if (req.cookies.token != "") {
    const email = jwt.verify(req.cookies.token,secretKey)
    const emailSpamProtector = jwt.sign({email},secretKey)
    res.cookie("emailSpamProtector",emailSpamProtector)
    res.render('forgot')
  }
  else {
    req.flash('message', 'User did not exists.')
    res.redirect('/auth')
  }
})
app.post('/forgot', async (req, res) => {
  const { email } = req.body
  console.log(req.cookies.token)
  let emailSpamProtector = req.cookies.emailSpamProtector
  
  let user = await userSchema.findOne({ email })
  if (user && emailSpamProtector) {
    const key = jwt.sign({ id: user._id }, secretKey, { expiresIn: '5m' });
    const link = `http://192.168.0.103:4000/forgot/password/${key}/${email}`
    
    sendRecoveryMail(email, link)
    console.log(link)
    
    let authKey = await userSchema.findOne({email})
    authKey.authkey = key
    await authKey.save()
    console.log(req.cookies.token)
    res.cookie("emailSpamProtector","")
    res.render('checkmail', { email })
  }
  else {
    req.flash('message', 'User did not exists.')
    res.redirect('/auth')
  }

})

app.get('/forgot/password/:token/:email', async (req, res) => {
  const key = req.params.token
  let user = await userSchema.findOne({email:req.params.email})
  try {
    if(user.authkey){
      let token = jwt.verify(key, secretKey)
      if (token) {
        res.render('amendpassword', { key })
      }
    }
    else{
      throw new Error("Token is being used")
    }
  }
  catch {
    console.error("JWT Token got expired!")
    req.flash('message', 'Link is expired!')
    res.redirect('/auth')
  }
})
app.post('/forgot/password/verify/:token', async (req, res) => {
  const rawToken = req.params.token;
  try {
    let decodedToken = jwt.verify(rawToken, secretKey);
    let user = await userSchema.findOne({ _id: decodedToken.id });

    if(user.authkey){
      bcrypt.genSalt(10, (err, salt) => {
        const { password } = req.body;
        bcrypt.hash(password, salt, async (err, hash) => {
          user.password = hash;
          user.authkey = null;
          user.sessions = user.sessions.filter(session => session !== rawToken);
          await user.save();
  
          invalidateToken(rawToken); // Invalidate the raw token string

          if(req.cookies.token != ""){
            res.redirect('/signin')
          }
          else{
            req.flash('message', 'Link is Invalid!')
            res.redirect('/auth')
          }
        });
      });
    }
    else{
      console.error("JWT Token got expired!")
      req.flash('message', 'Link is expired!')
      res.redirect('/auth')
    }
  }
  catch{
    req.flash('message','')
  }
});
app.get('/auth', (req, res) => {
  const token = req.cookies.token
  let msg;
  try {
    msg = req.flash('message')
  }
  catch {
    msg = null
  }
  res.render('authorized', { token, msg })
})
app.get('/success', (req, res) => {
  // const token = req.cookies.token
  let msg;
  try {
    msg = req.flash('message')
  }
  catch {
    msg = null
  }
  res.render('success', { msg })
})

app.get("/profile",isLoggedIn,async(req,res)=>{
let token = jwt.verify(req.cookies.token, secretKey);
const { email} = token;

let user = await userSchema.findOne({ email });
let {sessions} = user

// Filter out the current session token
sessions = sessions.filter(element => element != req.cookies.token);
// Decode remaining sessions
sessions.forEach((element, index) => {
    const decodedToken = jwt.verify(element, secretKey);
    sessions[index] = {decodedToken,Token:sessions[index]};
});
// Save the updated sessions back to the user

let date = user.date;
const Alltodos = await todoSchema.find({ email });
const todoLength = Alltodos.length;

let checked = [];
Alltodos.forEach(element => {
    let check = Number(element.checked);
    if (check) {
        checked.push(check);
    }
});

const userAgent = req.headers['user-agent'];
res.render("profile", { email, token, date, checked, todoLength, token, sessions });

})
app.post('/profile/delete/:email',(req,res)=>{
  const token = jwt.sign(req.params.email,secretKey)
  res.cookie("AccountDeletionToken",token)

  res.redirect('/delete')
})

app.get('/delete',isLoggedIn,async(req,res)=>{
  try{
    const verifier = jwt.verify(req.cookies.AccountDeletionToken,secretKey)
    res.render('delete')
  }
  catch{
    req.flash('message','User does not exists.')
    res.redirect('/auth')
  }
})

app.get('/account/delete/password',(req,res)=>{
  try{
    const verifier = jwt.verify(req.cookies.AccountDeletionToken,secretKey)
    res.render('terminate')
  }
  catch{
    req.flash('message','User does not exists.')
    res.redirect('/auth')
  }
})
app.post('/account/delete/password',async(req,res)=>{
  try {
    const { password } = req.body; // Correct destructuring
    const verifier = jwt.verify(req.cookies.AccountDeletionToken, secretKey);
    let user = await userSchema.findOne({ email: verifier }); // Ensure you use verifier.email to find the user
    
    if (user){
      const isPasswordCorrect = await bcrypt.compare(password, user.password); // Verify the password
      if (!isPasswordCorrect) {
        req.flash('message', "Invalid Password!");
        res.clearCookie('AccountDeletionToken');
        res.redirect('/auth');
      }
      else{
        await userSchema.deleteOne({ email: verifier }); // Delete the account
        await todoSchema.deleteMany({ email: verifier })
        res.clearCookie('token');
        res.clearCookie('AccountDeletionToken')

        req.flash('message',`Successfully deleted your account: ${verifier}`)
        res.redirect('/success'); 
      }
    } 
    else {
      console.log("User doesnt exists")
      req.flash('message', "User does not exist.");
      res.redirect('/auth')
    }
  } catch (error) {
    console.log(error)
    res.clearCookie('AccountDeletionToken');
    req.flash('message', "An error occurred. Please try again.");
    return res.redirect('/auth')
  }
})
app.post('/profile/session/delete', async (req, res) => {
  try {
      const token = req.body.token;
      console.log('Received token:', token);

      if (!token) {
          return res.status(400).json({ success: false, message: 'Token is missing' });
      }

      const { email } = jwt.verify(token, secretKey);
      console.log('Email from token:', email);

      let user = await userSchema.updateOne(
          { email: email },
          { $pull: { sessions: token } }
      );

      if (user.nModified === 0) {
          return res.status(404).json({ success: false, message: 'No session found to delete' });
      }

      console.log('Session token removed:', user);
      res.json({ success: true, message: 'User  session deleted successfully' });
  } catch (error) {
      console.log('Error during deletion:', error.message);
      res.status(500).json({ success: false, message: 'Error deleting user session', error: error.message });
  }
});

app.listen(port, () => {
  console.log(`Server is listening on port:${port}`);
});