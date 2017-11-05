var nodemailer = require('nodemailer');
var smtpTransport = require('nodemailer-smtp-transport');
var async = require('async');
var crypto = require('crypto');
var User = require('../models/user');
var secret = require('../secrets/secret');

module.exports = (app, passport) => {
    app.get('/', (req, res, next) => {
        res.render('index', { title: 'Index || Experts App' });
    });

    app.get('/signup', ( req, res ) => {
        var errors = req.flash('error');
        console.log(errors);
        res.render('user/signup', { title: 'Sign Up || Experts App', messages: errors, hasErrors: errors.length > 0 });
    });

    app.post('/signup', validate ,passport.authenticate('local.signup', {
        successRedirect: '/home',
        failureRedirect: '/signup',
        failureFlash: true
    }));
    app.get('/login', ( req, res ) => {
        var errors = req.flash('error');
        res.render('user/login', { title: 'Log In || Experts App', messages: errors, hasErrors: errors.length > 0 });
    });

    app.post('/login', loginValidate ,passport.authenticate('local.login', {
        successRedirect: '/home',
        failureRedirect: '/login',
        failureFlash: true
    }));

    app.get('/home', (req, res) => {
        res.render('home', {title: 'Home || Experts App'});
    });

    app.get('/forgot', (req, res) => {
        res.render('user/forgot', {title: 'Request for password reset'});
    });

    app.post('/forgot', (req, res, next) => {
        async.waterfall([
            //Generate the token 
            function(callback){
                crypto.randomBytes(20, (err, buf) => {
                    var rand = buf.toString('hex');
                    callback(err, rand);
                });
            },
            // Check user is exist in database and set password token in database
            function(rand, callback) {
                User.findOne({'email': req.body.email}, (err, user) => {
                    if(!user){
                        req.flash('error', 'No Account Exist');
                        return res.redirect('/forgot');
                    }

                    user.passwordResetToken = rand;
                    user.passwordResetExpires = Date.now() + 60*60*1000;

                    user.save((err) => {
                        callback(err, rand, user)
                    })
                })
            },
            // this function is to sent email to the user
            function(rand, user, callback) {
                var smtpTransport = nodemailer.createTransport({
                    service: 'Gmail',
                    auth: {
                        user: secret.auth.user,
                        pass: secret.auth.pass
                    }
                });
                
            }
        ])
    });
};


function validate(req, res, next) {
    req.checkBody('fullname', 'Full Name is Required').notEmpty();
    req.checkBody('fullname', 'Fullname not be Less than 5 Charaters').isLength({min: 5});
    req.checkBody('email', 'Email is Required').notEmpty();
    req.checkBody('email', 'Email is Invalid').isEmail();
    req.checkBody('password', 'Password is required').notEmpty();
    req.checkBody('password', 'Password not be less than 6 characters').isLength({min: 6});
    req.checkBody('password', 'Password must have atleast 1 Number and 1 Character').matches(/^(?=.*\d)(?=.*[a-zA-Z])[a-zA-Z0-9]{6,}$/, "i");

    var errors = req.validationErrors();

    if(errors) {
        var messages = [];
        errors.forEach((error) => {
            messages.push(error.msg);            
        });

        req.flash('error', messages);
        res.redirect('/signup');
    } else {
        return next();
    }
}

function loginValidate(req, res, next) {
    req.checkBody('email', 'Email is Required').notEmpty();
    req.checkBody('email', 'Email is Invalid').isEmail();
    req.checkBody('password', 'Password is required').notEmpty();
    req.checkBody('password', 'Password not be less than 6 characters').isLength({min: 6});
    req.checkBody('password', 'Password must have atleast 1 Number and 1 Character').matches(/^(?=.*\d)(?=.*[a-zA-Z])[a-zA-Z0-9]{6,}$/, "i");

    var loginErrors = req.validationErrors();

    if(loginErrors) {
        var messages = [];
        loginErrors.forEach((error) => {
            messages.push(error.msg);            
        });

        req.flash('error', messages);
        res.redirect('/login');
    } else {
        return next();
    }
}
