const bcrypt = require('bcryptjs');
const validator = require('validator');
const jwt = require('jsonwebtoken');

const User = require('../models/user');
const Post = require('../models/post');

module.exports = {
    createUser: async function({ userInput }, req) {
        // const email = userInput.email;
        const errors = [];
        if(!validator.isEmail(userInput.email)) {
            errors.push({
                message: 'Email is invalid'
            });
        }
        if(validator.isEmpty(userInput.password)) {
            errors.push({
                message: 'Password invalid'
            });
        }
        if(errors.length > 0) {
            const error = new Error('Invalid input');
            error.data = errors;
            error.code = 422;
            throw error;
        }
        const existingUser = await User.findOne({ email: userInput.email }); 
        if(existingUser) {
            const error = new Error('User exists');
            throw error;
        }

        const hashedPassword = await bcrypt.hash(userInput.password, 12);
        const user = new User({
            email: userInput.email,
            name: userInput.name,
            password: hashedPassword
        });

        const createdUser = await user.save();
        return {
            ...createdUser._doc,
            _id: createdUser._id.toString()
        };
    },

    login: async function({ email, password }, req) {
        const user = await User.findOne({ email: email });
        if(!user) {
            const error = new Error('No user found');
            throw error;
        }

        const isMatched = await bcrypt.compare(password, user.password);
        if(!isMatched) {
            const error = new Error('Password incorrect');
            throw error;
        }

        const token = jwt.sign({
            email: email,
            userId: user._id.toString()
        }, 'marauders', {
            expiresIn: '1h'
        });

        return {
            token: token,
            userId: user._id.toString()
        };
    },
    createPost: async function({ postData }, req) {
        if(!req.isAuth) {
            const error = new Error('Not authenticated');
            error.statusCode = 401;
            throw error;
        }
        const errors = [];
        if(validator.isEmpty(postData.title) || !validator.isLength(postData.title, { min: 5 })) {
            errors.push({
                message: 'Title invalid'
            });
        }

        if(errors.length > 0) {
            const error = new Error('Invalid input');
            error.data = errors;
            error.code = 422;
            throw error;
        }

        const user = await User.findById(req.userId);
        if(!user) {
            const error = new Error('Invalid user');
            error.statusCode = 401;
            throw error;
        }
        const post = new Post({
            title: postData.title,
            content: postData.content,
            imageUrl: postData.imageUrl,
            creator: user
        });

        const savedPost = await post.save();
        user.posts.push(savedPost);
        await user.save();
        return {
            ...savedPost._doc,
            _id: savedPost._id.toString(),
            createdAt: savedPost.createdAt.toISOString(),   
            updatedAt: savedPost.updatedAt.toISOString(),   
        };
    },
    getPosts: async function(args, req) {
        if(!req.isAuth) {
            const error = new Error('Not authenticated');
            error.statusCode = 401;
            throw error;
        }
        const currentPage = args.page || 1;
        const perPage = 2;
        const posts = await Post.find().populate('creator').sort({ createdAt: -1 }).skip((currentPage - 1) * perPage).limit(perPage);
        const totalPosts = await Post.find().countDocuments();
        // const posts = await Post.find()
        //                     .sort({ createdAt: -1 })
        //                     .populate('creator');
        return {
            posts: posts.map(p => {
                return {
                    ...p._doc,
                    _id: p._id.toString(),
                    createdAt: p.createdAt.toISOString(),
                    updatedAt: p.updatedAt.toISOString()
                }
            }),
            totalPosts: totalPosts
        };
    },
    getPost: async function({ postId }, req) {
        if(!req.isAuth) {
            const error = new Error('Not authenticated');
            error.statusCode = 401;
            throw error;
        }

        const post = await Post.findById(postId).populate('creator');
        console.log(post);
        if(!post) {
            const error = new Error('No post found');
            error.statusCode = 401;
            throw error;
        }

        return {
            ...post._doc,
            _id: post._id.toString(),
            createdAt: post.createdAt.toString(),
            updatedAt: post.updatedAt.toString()
        };
    },
    editPost: async function({ postId, postData }, req) {
        if(!req.isAuth) {
            const error = new Error('Not authenticated');
            error.statusCode = 401;
            throw error;
        }

        const post = await Post.findById(postId).populate('creator');
        // console.log(post);
        if(!post) {
            const error = new Error('No post found');
            error.statusCode = 401;
            throw error;
        }

        if(post.creator._id.toString() !== req.userId.toString()) {
            const error = new Error('Invalid authentication');
            error.statusCode = 401;
            throw error;
        }

        post.title = postData.title;
        post.content = postData.content;

        if(postData.imageUrl != 'undefined') {
            post.imageUrl = postData.imageUrl;
        }
        const updatedPost = await post.save();
        return {
            ...updatedPost._doc,
            _id: updatedPost._id.toString(),
            createdAt: updatedPost.createdAt.toISOString(),
            updatedAt: updatedPost.updatedAt.toISOString()
        };
    }
};