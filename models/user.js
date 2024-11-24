require('dotenv').config();
const mongoose = require('mongoose')

mongoose.connect(process.env.MONGODB_URL);
  
let userSchema = mongoose.Schema({
    username:String,
    email:String,
    password:String,
    todos:[{type:mongoose.Schema.Types.ObjectId}],
    authkey:String,
    date:String,
    sessions: [String], // Allows storing objects
})

module.exports = mongoose.model('user',userSchema)