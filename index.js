const express = require("express");
const mongoose = require("mongoose");
const joi = require('joi');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
require("dotenv").config();
const app = express();
const {UserSchema} = require('./models/user');

const port = process.env.PORT || 3000;

app.use(express.json());

mongoose.connect(process.env.MONGODB_URI);

app.get('/', (req, res) => {
    const token = req.headers['x-access-token'];
    if(!token) return res.send({message: 'Você não está logado'});
    const logged = jwt.verify(token, process.env.SECRET);

    if(logged) return res.send({message: 'Você está logado'});
    else return res.send({message: 'Você não está logado'});
});

app.post('/signup', async (req, res) => {
    const data = req.body;

    //validando dados do usuário
    const validation = joi.object({
        userName: joi.string().required(),
        email: joi.email().required(),
        password: joi.string().required(),
    });

    const { error } = validation.validate(data);
    if(error) return res.status(406).send(error.message);

    //verificar se usuário já existe
    const bdUser = await UserSchema.exists({
        $or: [{email: data.email}, {userName: data.userName}]
    });
    if(bdUser) return res.status(406).send({message: "Usuário já existe"});

    const hash = await bcrypt.hash(data.password, 10);
    const newUser = new UserSchema({
        userName: data.userName,
        email: data.email,
        password: hash,
        verified: false,
    });
    newUser.save();

    //sending email


    return res.status(200).send({message: "Ok"});
});

app.post('/login', async (req, res) => {
    const data = req.body;

    const validation = joi.object({
        email: joi.string().required(),
        password: joi.string().required(),
    });

    const {error} = validation.validate(data);

    if(error) return res.status(406).send(error.message);

    // search
    const user = await UserSchema.findOne({email: data.email});

    if(!user) return res.status(401).json({ message: "Invalid credentials" });

    const check = bcrypt.compare(data.password, user.password);
    
    if(!check) return res.status(401).json({ message: "Invalid credentials" });

    if(!user.verified) return res.status(500).json({message: "Please verify your email"});

    const token = jwt.sign(
        {userId: user._id}, process.env.SECRET,
        {expiresIn: 10 * 60 * 60}
    )
    return res.status(200).send({token: token})

});

app.get('/list', async (req, res) => {
    const q = await UserSchema.find({});
    return res.send({res: q});
});

app.listen(port, () => {
    console.log(`Server running at ${port}`);
});