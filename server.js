const express = require('express');
const app = express() 
const https = require('https')
const http = require('http')
const path = require('path');
const mongoose = require('mongoose')
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require("express-rate-limit");
const fs = require('fs');

const options = {
  key: fs.readFileSync(__dirname + '/key.pem'),
  cert: fs.readFileSync(__dirname + '/certificate.crt'),
};
const limiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 150
});

app.use(limiter);
app.use(helmet());
app.use (bodyParser.json ({limit: '10mb', extended: true}))
app.use (bodyParser.urlencoded ({limit: '10mb', extended: true}))
app.use(cors());
app.use(express.json())
app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.json())
const nodemailer = require('nodemailer');
const { createCipher } = require('crypto');
const { Int32 } = require('mongodb');
const server = https.createServer(options, app)
var httpsServer = https.createServer(options, app);
httpsServer.listen(3030, function(){
  console.log("HTTPS on port " + 3030);
})
var io = require('socket.io')(server);

let transporter = nodemailer.createTransport({ //Создание почтового бота
    service: 'gmail',
    pool: true,
    auth: {
        user: 'no.reply.christopher.robin.school@gmail.com',
        pass: 'KdbjjHG57Mskq'
    },
    tls: {
        rejectUnauthorized: false
    }
})

const Schema = mongoose.Schema;
const userScheme = new Schema({
    name: String,
    surname: String,
    email: String,
    gender: String,
    state: String,
    city: String,
    about: String,
    age: String,
    avatar: String,
    hobbies: Array,
    password: String,
    role: String,
    user_id: String,
    sessionid: String,
    extra_password: String,
    chats: Object,
    banned: Boolean,
    ban_time: Array,
    reason: String,
    ban_images: Array,
});
const User = mongoose.model("User", userScheme);
const codeScheme = new Schema({
    email: String,
    code: String,
    date: String,
    hours: String,
    minutes: String,
});

const Code = mongoose.model("Code", codeScheme);

const photoScheme = new Schema({
    photo: { data: String, contentType: String },
});

const Photo = mongoose.model("Photo", photoScheme);

const videoScheme = new Schema({
    video: { data: String, contentType: String },
});

const Video = mongoose.model("Video", videoScheme);

const chatScheme = new Schema({
    users: Array,
    in_block_first: Boolean,
    in_block_second: Boolean,
    chat: Array,
});

const Chat = mongoose.model("Chat", chatScheme);

app.post('/code',function(req,res){ //код подтверждения
    console.log(req.body, 'code')
    let email = 0
    let reg_email = 0
    async function get(){
        await User.find({email: req.body.email}).exec(function(err, person) {
            if (err) throw err;
            if(person.length != 0){
                email = 1
            }
        });
        await Code.find({email: req.body.email}).exec(function(err, person) {
            if(person.length != 0){
                let em = person[0]
                console.log('email', em.email);
                if (err) throw err;
                if(em.email != undefined){
                    reg_email = 1
                }
            }
            check()
        })
        let check = function(){
            if(email == 0){
                let now = new Date()
                let regCode = Math.floor(Math.random() * (999999999 - 100000000 + 1)) + 100000000
                console.log(regCode)
                if(reg_email == 0){
                    const code = new Code({
                        email: req.body.email,
                        code: regCode,
                        date: now.getDate(),
                        hours: now.getHours(),
                        minutes: now.getMinutes(),
                    });
                    code.save(function(err){
                        if(err) return console.log(err);
                        console.log('Код зарегистрирован!')
                    });
                }
                else{
                    Code.updateOne({email: req.body.email}, {$set: {code: regCode.toString(), date: now.getDate(), hours: now.getHours(), minutes: now.getMinutes(),}}, function(err){
                        if(err) return console.log(err);
                        console.log('Код обновлен!')
                    });
                }
                transporter.sendMail({
                    from: '"no-reply_Christopher Robin School" <no.reply.christopher.robin.school@gmail.com>',
                    to: req.body.email,
                    subject: "Access code",
                    text: "Your access code: " + regCode + ". It'll work for an hour" + "\n\n\nIf it weren't you, just ignore this email",
                })
                res.send('success');
                console.log(email, reg_email)
            }
            else{
                console.log('invalid email')
                res.send('invalid email');
            }
        }
    }
    get()
});

app.post('/registration',function(req,res){ //регистрация
    console.log(req.body, 'registration')
    function check(){
        Code.find({email: req.body.email}).exec(function(err, person) {
            if(person.length != 0 && person[0].code == req.body.code){
                let result = ''
                let result2 = ''
                async function makeId(){
                    let letters = '0123456789qwertyuiopasdfghjklzxcvbnm'
                    let maximum = letters.length - 1
                    for(let i = 0; i < 15; i++){
                        result += letters[Math.floor( Math.random() * maximum)]
                    }
                    Code.find({user_id: result}).exec(function(err, person) {
                        if(person.length != 0){
                            result = ''
                            makeId()
                        }
                    })
                }
                function makeSessionId(){
                    let letters = '0123456789qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM'
                    let maximum = letters.length - 1
                    for(let i = 0; i < 128; i++){
                        result2 += letters[Math.floor( Math.random() * maximum)]
                    }
                    Code.find({sessionid: result2}).exec(function(err, person) {
                        if(person.length != 0){
                            result2 = ''
                            makeSessionId()
                        }
                    })
                }
                makeId()
                makeSessionId()
                if(check_text(req.body.name, 20) && check_text(req.body.surname, 20) && check_text(req.body.state, 25) && check_text(req.body.city, 25) && check_text(req.body.password, 15)){
                    if(req.body.gender == 'Male' || req.body.gender == 'Female' || req.body.gender == 'Other'){
                        let password
                        bcrypt.hash(req.body.password, 10, function(err, hash) {
                            const user = new User({
                                name: req.body.name,
                                surname: req.body.surname,
                                email: req.body.email,
                                gender: req.body.gender,
                                state: req.body.state,
                                city: req.body.city,
                                about: '',
                                age: req.body.age,
                                avatar: '',
                                hobbies: [],
                                password: hash,
                                role: 'user',
                                user_id: result,
                                sessionid: result2,
                                extra_password: '',
                                chats: {},
                                banned: false,
                                ban_time: [],
                                reason: '',
                                ban_images: [],
                            });
                            user.save(function(err){
                                if(err) return console.log(err);
                                console.log('Новый пользователь зарегистрирован!')
                            });
                            Code.findOneAndRemove({email: req.body.email}).exec(function(err){
                                if(err) throw err
                            })
                            res.send('reg successful');
                        });
                    }
                }
            }
            else{
                res.send('reg failed');
            }
        })
    } 
    check()
});

app.post('/login',function(req,res){ // логин
    console.log(req.body, 'login')
    User.find({email: req.body.email}, {sessionid: 1, user_id: 1, role: 1, password: 1}).exec(function(err, person) {
        if (err) throw err;
        if(person.length != 0){
            bcrypt.compare(req.body.password, person[0].password, function(err, result) {
                if(result){
                    console.log('Log in')
                    res.send(JSON.stringify({sessionid: person[0].sessionid, user_id: person[0].user_id, role: person[0].role}));
                }
                else{
                    res.send(JSON.stringify('login failed'));
                }
            });
        }
        else{
            res.send(JSON.stringify('login failed'));
        }
    });
})

function updateREG_CODE(){ //удалить неактивные коды подтверждения
    let now = new Date()
    console.log('updateREG_CODE')
    async function get(){
        Code.find().exec(function(err, person) {
            for(let i = 0; i < person.length; i++){
                if(now.getDate() == person[i].date){
                    if(now.getHours() * 60 + now.getMinutes() - person[i].hours * 60 - person[i].minutes >= 60){
                        Code.findOneAndRemove({email: person[i].email}).exec(function(err){
                            if(err) throw err
                        })
                        console.log('delete')
                    }
                }
                else{
                    if(now.getMinutes() + person[i].minutes >= 60){
                        Code.findOneAndRemove({email: person[i].email}).exec(function(err){
                            if(err) throw err
                        })
                    }
                }
            }
        })
    }
    get()
}

setInterval(updateREG_CODE, 600000)

function updateBANNED_USERS(){
    let now = new Date()
    let now_time = new Date(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), now.getUTCHours(), now.getUTCMinutes())
    console.log('updateBANNED_USERS')
    async function get(){
        User.find({banned: true, ban_time: { $ne: ['forever'] }}).exec(function(err, person) {
            for(let i = 0; i < person.length; i++){
                let ban_time = new Date(person[i].ban_time[0], person[i].ban_time[1], person[i].ban_time[2], person[i].ban_time[3], person[i].ban_time[4])
                if(now_time - ban_time >= 86400000){
                    person[i].banned = false
                    person[i].ban_time = []
                    person[i].reason = ''
                    person[i].ban_images = []
                    person[i].save()
                }
            }
        })
    }
    get()
}

setInterval(updateBANNED_USERS, 600000)

app.post('/getInformation',function(req,res){ // информация о пользователе
    User.find({ email: req.body.email, sessionid: req.body.sessionid }).exec(function(err, user) {
        if(user.length != 0){
            console.log('GetInfo')
            res.send(JSON.stringify(user[0]));
        }
        else res.send('310')
    })
})

app.post('/updateUser',function(req,res){ // обновление профиля
    console.log(req.body, 'updateUser')
    User.find({ email: req.body.email, sessionid: req.body.sessionid }).exec(function(err, person) {
        if(person.length != 0){
            if (err) throw err;
            console.log('updateUser')
            if(check_text(req.body.name, 20) && check_text(req.body.surname, 20) && check_text(req.body.state, 25) && check_text(req.body.city, 25) && check_text(req.body.about, 300)){
                for(let i = 0; i < req.body.hobbies.length; i++){
                    if(check_text(req.body.hobbies[i], 30) == false) return
                }
                if(req.body.gender == 'Male' || req.body.gender == 'Female' || req.body.gender == 'Other'){
                    person[0].name = req.body.name
                    person[0].surname = req.body.surname
                    person[0].avatar = req.body.avatar
                    person[0].about = req.body.about
                    person[0].hobbies = req.body.hobbies
                    person[0].email = req.body.email
                    person[0].state = req.body.state
                    person[0].city = req.body.city
                    person[0].gender = req.body.gender
                    async function save(){
                        await person[0].save() 
                    }
                    save()
                    res.send('success');
                }
            }
        }
    })
})

app.post('/getSearchList', (req, res) => {
    console.log('getSearchList')
    if(req.body.filters.state_filters.length == 0 && req.body.filters.name_filters.length == 0 && req.body.filters.surname_filters.length == 0 && req.body.filters.gender_filters.length == 0){
        User.find({ email: { $ne: req.body.email } }, { email: 0, _id: 0, password: 0, extra_password: 0, chats: 0, sessionid: 0 }).exec(function(err, users) {
            if (err) throw err;
            let send = []
            let date = new Date()
            let day = date.getDate()
            let month = date.getMonth() + 1
            let year = date.getFullYear()
            if(users.length == 0) res.send([])
            for(let i = 0; i < users.length; i++){
                let age = 0
                if(month < users[i].age.slice(5,7)) age = year - users[i].age.slice(0,4) - 1
                else if(month > users[i].age.slice(5,7)) age = year - users[i].age.slice(0,4)
                else{
                    if(day >= users[i].age.slice(8)) age = year - users[i].age.slice(0,4)
                    else age = year - users[i].age.slice(0,4) - 1
                }
                console.log(age)
                if(age >= req.body.filters.age_filters_min && age <= req.body.filters.age_filters_max) send.push(users[i])
                if(i == users.length - 1) res.send(send.sort(() => Math.random() - 0.5))
            }
        });
    }
    else{
        let search = {}
        let cities = []
        if(req.body.filters.state_filters.length != 0) search.state = req.body.filters.state_filters[0]
        if(req.body.filters.name_filters.length != 0) search.name = { $regex: new RegExp("^" + req.body.filters.name_filters[0].toLowerCase(), "i") }
        if(req.body.filters.surname_filters.length != 0) search.surname = { $regex: new RegExp("^" + req.body.filters.surname_filters[0].toLowerCase(), "i") }
        if(req.body.filters.gender_filters.length != 0) search.gender = req.body.filters.gender_filters[0]
        if(req.body.filters.city_filters.length != 0){
            for(let i = 0; i < req.body.filters.city_filters.length; i++){
                cities.push({city: req.body.filters.city_filters[i]})
            }
        }
        if(cities.length != 0) search.$or = cities
        console.log(search)
        User.find(search, {email: 0, _id: 0, password: 0, extra_password: 0, chats: 0, sessionid: 0}).exec(function(err, users) {
            if (err) throw err;
            let send = []
            let date = new Date()
            let day = date.getDate()
            let month = date.getMonth() + 1
            let year = date.getFullYear()
            if(users.length == 0) res.send([])
            for(let i = 0; i < users.length; i++){
                let age = 0
                if(month < users[i].age.slice(5,7)) age = year - users[i].age.slice(0,4) - 1
                else if(month > users[i].age.slice(5,7)) age = year - users[i].age.slice(0,4)
                else{
                    if(day >= users[i].age.slice(8)) age = year - users[i].age.slice(0,4)
                    else age = year - users[i].age.slice(0,4) - 1
                }
                console.log(age)
                if(age >= req.body.filters.age_filters_min && age <= req.body.filters.age_filters_max) send.push(users[i])
                if(i == users.length - 1) res.send(send.sort(() => Math.random() - 0.5))
            }
        });
    }
})

app.post('/addChat', function(req,res){
    User.find({ email: req.body.email, sessionid: req.body.sessionid }).exec(function(err, user) {
        if(user.length != 0){
            Chat.find({ users: { $all: [ req.body.id, req.body.user_id ] } }).exec(function(err, chat) {
                console.log(chat)
                if(chat.length == 0){
                    User.find({ $or: [ {user_id: req.body.id}, {user_id: req.body.user_id} ]}, {name: 1, surname: 1}).exec(function(err, users) {
                        if(users.length == 2 && check_text(req.body.message, 500)){
                            let now = new Date()
                            const chat = new Chat({
                                users: [req.body.user_id, req.body.id],
                                in_block_first: false,
                                in_block_second: false,
                                chat: [{num: 0, message: {type: 'text', data: req.body.message}, from: req.body.user_id, for: req.body.id, send_time: [now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), now.getUTCHours(), now.getUTCMinutes()], read_time: [], show_for_first: true, show_for_second: true, changed: false, link: {}}],
                            });
                            chat.save(function(err){
                                if(err) return console.log(err);
                                console.log('Новый чат!')
                                res.send(JSON.stringify('OK'))
                            });
                        }
                    })
                }
                else res.send(JSON.stringify('EXIST'))
            })
        }
    })
})

app.post('/getChats', function(req,res){
    User.find({ email: req.body.email, sessionid: req.body.sessionid }).exec(function(err, user) {
        if(user.length != 0){
            Chat.find({ users: { $in: [ req.body.user_id ] } }, {users: 1, _id: 0}).exec(function(err, chats) {
                console.log(chats)
                res.send(chats)
            })
        }
    })
})

app.post('/getPrivateChat', function(req,res){
    User.find({ email: req.body.email, sessionid: req.body.sessionid }).exec(function(err, _user) {
        if(_user.length != 0){
            Chat.find({ users: { $all: req.body.users } }).exec(function(err, chat) {
                if(chat.length != 0){
                    User.find({ user_id: req.body.users[1] }, {_id: 0, name: 1, surname: 1}).exec(function(err, user) {
                        let mess
                        if(req.body.num == 0) mess = chat[0].chat.slice(-20)
                        else mess = chat[0].chat.slice(-20 - req.body.num, - req.body.num)
                        chat[0].chat = mess
                        res.send([chat, user[0].name + ' ' + user[0].surname])
                    })
                }
                else res.send(JSON.stringify('UNDEF'))
            })
        }
    })
})

app.post('/getGeneralChat', function(req,res){
    Chat.find({ users: ['All'] }).exec(function(err, chat) {
        let mess
        let chat_to_send = []
        for(let i = 0; i < chat[0].chat.length; i++){
            if(chat[0].chat[i].message != '') chat_to_send.push(chat[0].chat[i])
        }
        if(req.body.num == 0) mess = chat_to_send.slice(-20)
        else mess = chat_to_send.slice(-20 - req.body.num, - req.body.num)
        chat[0].chat = mess
        res.send(chat)
    })
})

app.post('/addPerson', function(req,res){
    User.find({ email: req.body.email, sessionid: req.body.sessionid }).exec(function(err, _user) {
        if(_user.length != 0 && req.body.admin_role == 'admin'){
            User.find({ email: req.body.person_email }).exec(function(err, user) {
                if(user.length == 0) res.send(JSON.stringify('No users'))
                else{
                    user[0].role = req.body.role
                    user[0].save()
                    res.send(JSON.stringify('OK'))
                }
            })
        }
    })
})

app.post('/getRandomChat', function(req,res){
    User.find({ email: req.body.email, sessionid: req.body.sessionid, role: req.body.role }).exec(function(err, _user) {
        if(_user.length != 0 && req.body.role == 'admin'){
            if(req.body.users == undefined){
                Chat.find({ users: ['General_chat_archive'] }).exec(function(err, chat) {
                    res.send(chat)
                })
            }
            else if(req.body.users.length == 0){
                Chat.countDocuments().exec(function(err, num) {
                    let number = Math.floor(Math.random() * (num - 2))
                    console.log(number)
                    Chat.find({ in_block_first: {$exists: true }}).skip(number).limit(1).exec(function(err, chat) {
                        let mess = chat[0].chat.slice(-20)
                        chat[0].chat = mess
                        res.send(chat)
                    })
                })
            }
            else{
                Chat.find({ users: req.body.users}).exec(function(err, chat) {
                    let mess = chat[0].chat.slice(-20 - req.body.num, - req.body.num)
                    chat[0].chat = mess
                    res.send(chat)
                })
            }
        }
    })
})

app.post('/banUser', function(req,res){
    let data = req.body
    User.find({ email: data.email, sessionid: data.sessionid, role: data.role }).exec(function(err, _user) {
        if(_user.length != 0 && data.role == 'admin'){
            User.find({ user_id: data.user }).exec(function(err, user) {
                if(data.ban == '24'){
                    let now = new Date()
                    user[0].banned = true
                    user[0].ban_time = [now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), now.getUTCHours(), now.getUTCMinutes()]
                    user[0].reason = data.reason
                    user[0].ban_images = data.images
                    user[0].save()
                    if(users[user.user_id]) users[user.user_id].emit('ban_user', {date: [now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), now.getUTCHours(), now.getUTCMinutes()], reason: data.reason, images: data.images})
                }
                else if(data.ban == 'forever'){
                    user[0].banned = true
                    user[0].ban_time = ['forever']
                    user[0].reason = data.reason
                    user[0].ban_images = data.images
                    user[0].save()
                    if(users[user.user_id]) users[user.user_id].emit('ban_user', {date: ['forever'], reason: data.reason, images: data.data})
                }
            })
        }
    })
})

app.post('/deleteArchive', function(req,res){
    User.find({ email: req.body.email, sessionid: req.body.sessionid, role: req.body.role }).exec(function(err, _user) {
        if(_user.length != 0 && req.body.role == 'admin'){
            Chat.find({ users: ['General_chat_archive'] }).exec(function(err, chat) {
                chat[0].chat = []
                chat[0].save()
                res.send(JSON.stringify('OK'))
            })
        }
    })
})

let users = {}
let general_chat = {}
io.sockets.on('connection', function(socket){
    socket.on('error', (err) => {
        console.log(err)
    });
    socket.on('new_user', (data) => {
        console.log('new_user')
        users[data] = socket
    })
    socket.on('disconnect', () => {
        console.log('leave user')
        for(let key in users){
            if(users[key] == socket){
                delete users[key]
                if(general_chat[key]){
                    for(let key1 in general_chat){
                        try{
                            general_chat[key1].socket.emit('leave_general_chat', {name: general_chat[key].name, role: general_chat[key].role, id: general_chat[key].id})
                        }catch(err){}
                    }    
                    delete general_chat[key]
                }
                return
            }
        }
    })
    socket.on('get_info_for_chats', (data) => {
        User.find({ email: data.email, sessionid: data.sessionid }).exec(function(err, _user) {
            if(_user.length != 0){
                User.find({user_id: data.id}, {name: 1, surname: 1, avatar: 1, user_id: 1, gender: 1, _id: 0}).exec(function(err, user) {
                    Chat.find({ users: { $all: [ data.id, data.user_id ] } }, { chat: { $slice: -1 }, _id: 0}).limit(1).sort({$natural:-1}).exec(function(err, chat) {
                        console.log(chat[0].chat)
                        console.log(user[0].name)
                        users[data.user_id].emit('get_info_for_chats', [user[0], chat[0]])
                    })
                })
            }
        })
    })
    socket.on('new_message', (data) => {
        User.find({ email: data.email, sessionid: data.sessionid }).exec(function(err, _user) {
            if(_user.length != 0){
                User.find({user_id: data.from}).exec(function(err, user) {
                    if(data.users == undefined){
                        if(user[0].banned == false){
                            Chat.find({ users: ['All'] }).exec(function(err, chat) {
                                if(check_text(data.message, 600)){
                                    let now = new Date()
                                    chat[0].chat.push({num: chat[0].chat.slice(-1)[0].num + 1, from: data.from, message: {type: data.type, data: data.message}, name: data.name, role: data.role, send_time: [now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), now.getUTCHours(), now.getUTCMinutes()], changed: false, link: {}, deleted: false})
                                    if(chat[0].chat.length == 201){
                                        Chat.find({ users: ['General_chat_archive'] }).exec(function(err, chat_ar) {
                                            chat_ar[0].chat.push(chat[0].chat[0])
                                            chat[0].chat.shift()
                                            chat_ar[0].save()
                                            chat[0].save()
                                        })
                                    }
                                    else chat[0].save()
                                    for(let key in general_chat){
                                        try{
                                            general_chat[key].socket.emit('new_general_message', {num: chat[0].chat.slice(-1)[0].num, from: data.from, message: {type: data.type, data: data.message}, name: data.name, role: data.role, send_time: [now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), now.getUTCHours(), now.getUTCMinutes()], changed: false, link: {}, deleted: false})
                                        }catch(err){}
                                    }
                                }
                            })
                        }
                    }
                    else if(user[0].ban_time[0] != 'forever'){
                        Chat.find({ users: { $all: data.users } }).exec(function(err, chat) {
                            if(chat[0].in_block_first == false && chat[0].in_block_second == false && check_text(data.message, 3000)){
                                let now = new Date()
                                chat[0].chat.push({num: chat[0].chat.length, from: data.from, for: data.for, message: {type: data.type, data: data.message}, send_time: [now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), now.getUTCHours(), now.getUTCMinutes()], read_time: [], show_for_first: true, show_for_second: true, changed: false, link: {}})
                                new Promise(function(resolve) {
                                    resolve(chat[0].save())
                                })
                                .then(() => {
                                    try{
                                        users[chat[0].users[0]].emit('new_message', {num: chat[0].chat.length - 1, from: data.from, for: data.for, message: {type: data.type, data: data.message}, send_time: [now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), now.getUTCHours(), now.getUTCMinutes()], read_time: [], show_for_first: true, show_for_second: true, changed: false, link: {}})
                                    }catch(err){}
                                    try{
                                        users[chat[0].users[1]].emit('new_message', {num: chat[0].chat.length - 1, from: data.from, for: data.for, message: {type: data.type, data: data.message}, send_time: [now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), now.getUTCHours(), now.getUTCMinutes()], read_time: [], show_for_first: true, show_for_second: true, changed: false, link: {}})
                                    }catch(err){}
                                })
                            }
                        })
                    }
                })
            }
        })
    })
    socket.on('read_message', (data) => {
        User.find({ email: data.email, sessionid: data.sessionid }).exec(function(err, _user) {
            if(_user.length != 0){
                let now = new Date()
                console.log(data)
                Chat.updateOne({'chat.num': data.chat.num, 'chat.from': data.chat.from, 'chat.for': data.chat.for},
                    {'$set': {
                        'chat.$.read_time': [now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), now.getUTCHours(), now.getUTCMinutes()],
                    }},
                        function(err,model) {
                    console.log(model)
                    if(model.nModified == 1){
                        try{
                            console.log('sended')
                            users[data.chat.from].emit('read_message', {num: data.chat.num, read_time: [now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), now.getUTCHours(), now.getUTCMinutes()]})
                        }catch(err){}
                    }
                });
            }
        })
    })
    socket.on('come_in_general_chat', (data) => {
        for(let key1 in general_chat){
            socket.emit('users_in_general_chat', {name: general_chat[key1].name, id: general_chat[key1].id, role: general_chat[key1].role})
        }
        general_chat[data.user_id] = {}
        general_chat[data.user_id].socket = socket
        general_chat[data.user_id].name = data.name
        general_chat[data.user_id].id = data.user_id
        general_chat[data.user_id].role = data.role
        for(let key in general_chat){
            try{
                general_chat[key].socket.emit('come_in_general_chat', {name: data.name, role: data.role, id: data.user_id})
            }catch(err){}
        }
    })
    socket.on('leave_general_chat', (data) => {
        delete general_chat[data.user_id]
        for(let key in general_chat){
            try{
                general_chat[key].socket.emit('leave_general_chat', {name: data.name, role: data.role, id: data.user_id})
            }catch(err){}
        }    
    })
    socket.on('delete_message', (data) => {
        User.find({ email: data.email, sessionid: data.sessionid, role: data.role }).exec(function(err, _user) {
            if(_user.length != 0 && data.role == 'admin'){
                if(data.users == undefined){
                    Chat.updateOne({'chat.num': data.num, 'chat.deleted': false},
                        {'$set': {
                            'chat.$.deleted': true,
                            'chat.$.message': '',
                        }},
                        function(err,model) {
                        console.log(model)
                        if(model.nModified == 1){
                            for(let key in general_chat){
                                try{
                                    general_chat[key].socket.emit('delete_message', {num: data.num})
                                }catch(err){}
                            }
                        }
                    });
                }
            }
        })
    })
    // socket.on('recon', (data) => {
    //     users[data.user_id] = socket
    //     User.find({email: data.email}, {banned: 1, _id: 0}).exec(function(err, user) {
    //         if(user[0].banned == false){
    //             if(data.users == undefined){
    //                 for(let key1 in general_chat){
    //                     socket.emit('users_in_general_chat', {name: general_chat[key1].name, id: general_chat[key1].id, role: general_chat[key1].role})
    //                 }
    //                 general_chat[data.user_id] = {}
    //                 general_chat[data.user_id].socket = socket
    //                 general_chat[data.user_id].name = data.name
    //                 general_chat[data.user_id].id = data.user_id
    //                 general_chat[data.user_id].role = data.role
    //                 console.log(data.num)
    //                 for(let key in general_chat){
    //                     try{
    //                         general_chat[key].socket.emit('come_in_general_chat', {name: data.name, role: data.role, id: data.user_id})
    //                     }catch(err){}
    //                 }
    //                 if(data.num){
    //                     Chat.find({ users: ['All']}, {chat: { $slice: data.num } }).exec(function(err, chat) {
    //                         for(let key1 in users){
    //                             try{
    //                                 console.log(key1)
    //                                 users[key1].emit('recon', {chat: data.chat})
    //                             }catch(err){}
    //                         }
    //                         console.log(data.num)
    //                     })
    //                 }
    //                 else{
    //                     Chat.find({ users: ['All']}).exec(function(err, chat) {
    //                         console.log(chat[0].chat.length)
    //                     })
    //                 }
    //             }
    //         }
    //     })
    // })
})

function check_text(text, size){
    if(text.length > size) return false
    let re = 'qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890~`!@"#№$;%^:&?*()_-=+{};,./<>| ' + "'"
    for(let i = 0; i < text.length; i++){
        if(re.lastIndexOf(text[i]) == -1){
            return false
        }
    }
    return true
}

async function start(){
    try{
        let url = 'mongodb://127.0.0.1:27017/'
        await mongoose.connect(url,{
            useNewUrlParser: true,
            useUnifiedTopology: true,
            useFindAndModify: false,
        })
        
        server.listen(3000, () => {
            console.log('Server listening at port 3000');
        });
        app.listen(3050, function(){
            console.log('Express server listening on port 3030');
        });

        // User.update(
        //     {name: 'Test'},
        //     {password: hash},
        //     {multi: true},
        //         function(err, res){
        //             console.log(res)
        //         });
        
    } catch(err){
        console.log(err)
    }
}

start()