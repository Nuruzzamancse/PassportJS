const express = require('express');
const router = express.Router();
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;


const User = require('../models/users');

//Home Page -Dhasborad
router.get('/',ensureAuthenticated, (req, res, next) => {
    res.render('index');
});

router.get('/register',function (req,res,next) {
    res.render('register')
})

router.get('/login',function (req,res,next) {
    res.render('login')
})

//Logout
router.get('/logout',function (req,res,next) {
    req.logout();
    req.flash('success_msg','Your are logged out');
    res.redirect('/login');

})

router.post('/register',function (req,res,next) {
    const name = req.body.name;
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;
    const password2 = req.body.password2;

    req.checkBody('name','Name field is required').notEmpty();
    req.checkBody('email','Email field is required').notEmpty();
    req.checkBody('password','Password field is required').notEmpty();
    req.checkBody('email','Email field is required').notEmpty();
    req.checkBody('email','Email must be a valid address').isEmail();
    req.checkBody('password2','Password dont match').equals(req.body.password);

    let errors = req.validationErrors();

    if(errors){
        res.render('register',{
            errors:errors
        })
    }else{

        const newUser = new User({
            name:name,
            username:username,
            email:email,
            password:password

        });

        User.registerUser(newUser,function (err,user) {

            if(err)
                throw err;
            req.flash('success_msg','You are Registered and you can login');
            res.redirect('/login');

        })

    }

})

//Local Strategg

passport.use(new LocalStrategy(function (username,password,done) {

    User.getUserByUserName(username,function (err,user) {
        if(err) throw err;
        if(!user)
        {
            return done(null,false,{message:'No user found.'})
        }
        User.comparePassword(password,user.password,function (err,isMatch) {
            if(isMatch)
            {
                return done(null,user);
            }else{
                return done(null,false,{message:'Wrong Password'})
            }
        })

    })

}));
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.getUserById(id, (err, user) => {
        done(err, user);
    });
});


//Login Processing

router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect:'/',
        failureRedirect:'/login',
        failureFlash: true
    })(req, res, next);
});


//Access Control

function ensureAuthenticated(req,res,next) {
    if(req.isAuthenticated()){
        return next();
    }else{
        req.flash('error_msg','You are not authorized to viw that page.')
        res.redirect('/login');
    }
}


module.exports =router;