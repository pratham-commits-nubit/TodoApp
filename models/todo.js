require('dotenv').config();
const mongoose = require('mongoose')

mongoose.connect(process.env.MONGODB_URL);

let todoSchema = mongoose.Schema({
    email:String,
    title:String,
    desc:String,
    timeStart:String,
    timeDead:String,
    dateStart:String,
    dateDead:String,
    checked:Boolean,

})

module.exports = mongoose.model('todo',todoSchema)