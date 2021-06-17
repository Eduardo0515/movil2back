const { Router } = require('express');
const router = Router();

const User = require('../models/userModel');
const verifyToken = require('./verifyToken');

const jwt = require('jsonwebtoken');
const config = require('../config');

router.post('/signup', async (req, res) => {
    try {
        const { username, email, password, repeatPassword } = req.body;
        const user = new User({
            username,
            email,
            password,
            repeatPassword,
        });
        if(!password.localeCompare(repeatPassword)==0){
            return res.status(500).send("La contraseña debe ser la misma en ambos campos");
        }
        user.password = await user.encryptPassword(password);
        user.repeatPassword = await user.encryptPassword(repeatPassword);
        await user.save();

        const token = jwt.sign({ id: user.id }, config.secret, {
            expiresIn: '24h'
        });
        res.status(200).json({ auth: true, token });
    } catch (e) {
        console.log(e);
        res.status(500).send('Ocurrió un problema al registrarse');
    }
});

router.post('/signin', async (req, res) => {
    try {
        const user = await User.findOne({ username: req.body.username });
        if (!user) {
            return res.status(404).send({ auth: false, token: null });
        }
        const validPassword = await user.validatePassword(req.body.password, user.password);
        if (!validPassword) {
            return res.status(401).send({ auth: false, token: null });
        }
        const token = jwt.sign({ id: user._id }, config.secret, {
            expiresIn: '24h'
        });
        res.status(200).json({ auth: true, token });
    } catch (e) {
        console.log(e);
        res.status(500).send('Ocurrió un problema al iniciar sesión');
    }
});

router.get('/logout', function(req,res){
    res.status(200).send({auth:false, token: null});
});

module.exports = router;