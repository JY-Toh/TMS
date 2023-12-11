const connection = require("./config/database")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcryptjs")

// Login a user => /login
exports.loginUser = async (req, res, next) => {
  try {
    const { username, password } = req.body

    if (username === "" || password === "") {
      res.status(400).json({
        success: false,
        message: "Error: Invalid login credentials"
      })
    }

    //find user in database
    const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [username])
    if (row.length === 0) {
      res.status(401).json({
        success: false,
        message: "Error: Invalid login credentials"
      })
    }

    const user = row[0]

    //Use bcrypt to compare password
    const passwordsMatch = await bcrypt.compare(password, user.password)
    if (!passwordsMatch) {
      res.status(400).json({
        success: false,
        message: "Error: Invalid login credentials"
      })
    }

    if (user.is_disabled === 1) {
      res.status(401).json({
        success: false,
        message: "Error: Invalid login credentials"
      })
    }

    sendToken(user, 200, res)
  } catch (e) {
    console.log(e)
  }
}

// Logout a user => /_logout
exports.logout = async (req, res, next) => {
  res.cookie("token", null, {
    expires: new Date(Date.now()),
    httpOnly: true
  })

  res.status(200).json({
    success: true,
    message: "Logged out"
  })
}

// Create a user => /register
exports.registerUser = async (req, res, next) => {
  try {
    let { username, email, password, grouplist } = req.body

    if (!req.body.email) {
      email = null
    }

    if (!req.body.grouplist) {
      grouplist = null
    }
    if (!req.body.username || !req.body.password) {
      res.status(400).json({
        success: false,
        message: "Error: Fill in Username and Password"
      })
    }

    // Check if password is provided, 8 > character > 10 and only include alphanumeric, number and special character
    if (password) {
      const passwordRegex = /^(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,10}$/
      if (!passwordRegex.test(password)) {
        res.status(400).json({
          success: false,
          message: "Error: Password must be 8-10 characters long, contain at least one number, one letter and one special character"
        })
      }
    } else {
      const hashPassword = await bcrypt.hash(password, 10)
      let result
      try {
        result = await connection.promise().execute("INSERT INTO user (username, password, email, grouplist, is_disabled) VALUES (?,?,?,?,?)", [username, hashPassword, email, grouplist, 0])
      } catch (e) {
        console.log(e)
        res.status(400).json({
          success: false,
          message: "Error: Failed to create new user"
        })
      }

      res.status(200).json({
        success: true,
        message: "User created successfully"
      })
    }
  } catch (e) {
    console.log(e)
  }
}

// Create and send token and save in cookie
const sendToken = (user, statusCode, res) => {
  // Create JWT Token
  const token = getJwtToken(user)

  // Options for cookie
  const options = {
    expires: new Date(Date.now() + process.env.COOKIE_EXPIRES_TIME * 24 * 60 * 60 * 1000),
    httpOnly: true
  }

  let decoded
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET)
  } catch (e) {
    console.log(e)
    res.status(400).json({
      success: false,
      message: "Token error"
    })
  }

  res
    .status(statusCode)
    .cookie("token", token, options)
    .json({
      success: true,
      message: "Welcome " + decoded.username + "!",
      token
    })
}

const getJwtToken = user => {
  try {
    return jwt.sign({ username: user.username }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_TIME
    })
  } catch (e) {
    console.log(e)
  }
}

//View user profile => /profile
exports.userProfile = async (req, res, next) => {
  try {
    const [row, fields] = await connection.promise().execute("SELECT * FROM user WHERE username = ?", [req.user.username])

    res.status(200).json({
      success: true,
      data: row
    })
  } catch (e) {
    console.log(e)
  }
}

//Update user profile => /profile/update
exports.updateProfile = async (req, res, next) => {
  try {
    const [row, fields] = await connection.promise().execute("SELECT * FROM user WHERE username = ?", [req.user.username])
    let changedEmail = true

    let update = ""
    if (req.body.email || req.body.email === "") {
      if (req.body.email === req.user.email) {
        changedEmail = false
      } else {
        const updateEmail = await connection.promise().execute("UPDATE user SET email = ? WHERE username = ?", [req.body.email, req.user.username])
        update += "Email successfully updated!"
      }
    }
    if (req.body.password) {
      const passwordRegex = /^(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,10}$/
      if (!passwordRegex.test(req.body.password)) {
        res.status(400).json({
          success: false,
          message: "Error: Password must be 8-10 characters long, contain at least one number, one letter and one special character"
        })
      }
      const hashPassword = await bcrypt.hash(req.body.password, 10)
      const updatePassword = await connection.promise().execute("UPDATE user SET password = ? WHERE username = ?", [hashPassword, req.user.username])
      update += "\nPassword successfully updated!"
    }

    if (changedEmail === false && update === "") {
      res.status(200).json({
        success: true,
        message: "Nothing changed"
      })
    } else {
      res.status(200).json({
        success: true,
        message: update
      })
    }
  } catch (e) {
    console.log(e)
  }
}

//View all users(Admin ONLY) => /viewUsers
exports.viewUsers = async (req, res, next) => {
  try {
    const [rows, fields] = await connection.promise().execute("SELECT * FROM user")

    res.status(200).json({
      success: true,
      data: rows
    })
  } catch (e) {
    console.log(e)
  }
}

//View all groups(Admin ONLY) => /viewGroups
exports.viewGroups = async (req, res, next) => {
  try {
    const [rows, fields] = await connection.promise().execute("SELECT * FROM usergroups")

    res.status(200).json({
      success: true,
      data: rows
    })
  } catch (e) {
    console.log(e)
  }
}

//Change status "Active/Disabled"(Admin ONLY) => /statusChange
exports.statusChange = async (req, res, next) => {
  try {
    const { username, is_disabled } = req.body

    try {
      results = await connection.promise().execute("UPDATE user SET is_disabled = ? WHERE username = ?", [is_disabled, username])
      if (results[0].affectedRows === 0) {
        console.log(results[0])
        res.status(400).json({
          success: false,
          message: "Error: No changes made"
        })
        // return next(new ErrorResponse("No changes made :("))
      }
    } catch (e) {
      console.log(e)
      res.status(400).json({
        success: false,
        message: "Error: Changing status"
      })
      return next(new ErrorResponse("Error changing status", 500))
    }

    res.status(200).json({
      success: true,
      message: req.user.username + "'s status is now " + req.body.is_disabled
    })
  } catch (e) {
    console.log(e)
  }
}

//Create new UserGroup(Admin ONLY) => /addGroup
exports.addGroup = async (req, res, next) => {
  try {
    const invalidName = !req.body.group_name || req.body.group_name == ""
    if (invalidName) {
      console.log("invalid name")
      res.status(400).json({
        success: false,
        message: "Error: Failed to create group"
      })
      // return next(new ErrorResponse("Creation failed!"), 418)
    }
    const [row, fields] = await connection.promise().execute("SELECT * FROM usergroups")
    if (row.some(group => group.group_name === req.body.group_name)) {
      console.log("Group exists")
      res.status(400).json({
        success: false,
        message: "Error: Group already exist"
      })
      // return next(new ErrorResponse("Group already exists!!"), 418)
    }

    const results = await connection.promise().execute("INSERT INTO usergroups VALUES (?)", [req.body.group_name])
    console.log("Created")

    res.status(200).json({
      success: true,
      message: req.body.group_name + " successfully created!"
    })
  } catch (e) {
    console.log(e)
  }
}

//Update user profile(Admin ONLY) => /updateUser
exports.updateUser = async (req, res, next) => {
  try {
    const [row, fields] = await connection.promise().execute("SELECT * FROM user WHERE username = ?", [req.body.username])
    // let changedEmail = true

    let update = ""
    if (req.body.email && req.body.email != "") {
      const updateEmail = await connection.promise().execute("UPDATE user SET email = ? WHERE username = ?", [req.body.email, req.body.username])
      update += "Email successfully updated!\n"
    }
    if (req.body.password) {
      const passwordRegex = /^(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,10}$/
      if (!passwordRegex.test(req.body.password)) {
        res.status(400).json({
          success: false,
          message: "Error: Password must be 8-10 characters long, contain at least one number, one letter and one special character"
        })
      }
      const hashPassword = await bcrypt.hash(req.body.password, 10)
      const updatePassword = await connection.promise().execute("UPDATE user SET password = ? WHERE username = ?", [hashPassword, req.body.username])
      update += " Password successfully updated!\n"
    }

    if (req.body.grouplist || req.body.grouplist === "") {
      const updateGrouplist = await connection.promise().execute("UPDATE user SET grouplist = ? WHERE username = ?", [req.body.grouplist, req.body.username])
      update += " Grouplist successfully updated!"
    }
    res.status(200).json({
      success: true,
      message: update
    })
  } catch (e) {
    console.log(e)
  }
}
