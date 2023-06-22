require("dotenv").config();
require("./config/database").connect();
const User = require("./model/user");
const express = require("express");
const auth = require("./middleware/auth");
const bcrypt = require('bcryptjs');
const jwt = require("jsonwebtoken");
const app = express();

app.use(express.json());
app.use(express.urlencoded());


app.post("/welcome", auth, (req, res) => {
  res.status(200).send("Welcome 🙌 ");
});

app.post("/register", async (req, res) => {
	// Our register logic starts here
	try {
		const { first_name, last_name, email, password } = req.body;

		// Validate user input
		if (!(email && password && first_name && last_name)) {
			res.status(400).send("All input is required");
		}

		// check if user already exist
		// Validate if user exist in our database
		const oldUser = await User.findOne({ email });

		if (oldUser) {
			return res.status(409).send("User Already Exist. Please Login");
		}

		//Encrypt user password
		encryptedPassword = await bcrypt.hash(password, 10);

		// Create user in our database
		const user = await User.create({
			first_name,
			last_name,
			email: email.toLowerCase(), // sanitize: convert email to lowercase
			password: encryptedPassword,
		});

		// Create token
		const token = jwt.sign(
			{ user_id: user._id, email },
			process.env.TOKEN_KEY,
			{
				expiresIn: "2h",
			}
		);
		// save user token
		user.token = token;

		// return new user
		res.status(201).json(user);
	} catch (err) {
		console.log(err);
	}
	// Our register logic ends here
});

app.post("/login", async (req, res) => {

  // Our login logic starts here
  try {
    // Get user input
    const { email, password } = req.body;

    // Validate user input
    if (!(email && password)) {
      res.status(400).send("All input is required");
    }
    // Validate if user exist in our database
    const user = await User.findOne({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
      // Create token
      const token = jwt.sign(
        { user_id: user._id, email },
        process.env.TOKEN_KEY,
        {
          expiresIn: "2h",
        }
      );

      // save user token
      user.token = token;

      // user
      res.status(200).json(user);
    }
    res.status(400).send("Invalid Credentials");
  } catch (err) {
    console.log(err);
  }
  // Our register logic ends here
});

app.put('/users/:id', async (req, res) => {
	try {
	  const { id } = req.params;
	  const { first_name, last_name, email, password } = req.body;
  
	  const user = await User.findByIdAndUpdate (id, {first_name, last_name, email, password}, {new :true });
  
	  if(!user) {
		return res.status(404).json({error: 'User not found'});
	  }
  
	  res.json(user);
	} catch (err) {
	  res.status (500).json ({error: 'Failed to update user'})
	}
})

app.delete('/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findByIdAndDelete(id);
    
    if(!user) {
      return res.status(404).json({error: 'User not found'});
    }

    res.json({ message : 'User deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete user scuccefully'})
  }
});

module.exports = app;