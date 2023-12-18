const connection = require("./config/database")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcryptjs")
const { authorizeRoles } = require("./auth")
const nodemailer = require("nodemailer")

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
    console.log("I am here in first line of /register")
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
        res.status(404).json({
          success: false,
          message: "Error: Password must be 8-10 characters long, contain at least one number, one letter and one special character"
        })
      } else {
        const hashPassword = await bcrypt.hash(password, 10)
        let result
        try {
          console.log(username + hashPassword + email + grouplist)
          result = await connection.promise().execute("INSERT INTO user (username, password, email, grouplist, is_disabled) VALUES (?,?,?,?,?)", [username, hashPassword, email, grouplist, 0])
        } catch (e) {
          console.log(e)
          res.status(404).json({
            success: false,
            message: "Error: Failed to create new user"
          })
        }

        res.status(200).json({
          success: true,
          message: "User created successfully"
        })
      }
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
    res.status(403).json({
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
        res.status(404).json({
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
        res.status(404).json({
          success: false,
          message: "Error: No changes made"
        })
        // return next(new ErrorResponse("No changes made :("))
      }
    } catch (e) {
      console.log(e)
      res.status(404).json({
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

//A2 APIs
//View all apps => /getApps
exports.getApps = async (req, res, next) => {
  try {
    const [rows, fields] = await connection.promise().query("SELECT * FROM application")
    res.status(200).json({
      success: true,
      data: rows
    })
  } catch (e) {
    console.log(e)
  }
}

//Create app => /createApp
exports.createApp = async (req, res, next) => {
  let { App_Acronym, App_Description, App_Rnumber, App_startDate, App_endDate, App_permit_create, App_permit_Open, App_permit_toDoList, App_permit_Doing, App_permit_Done } = req.body

  try {
    if (!App_Acronym || !App_Description || !App_Rnumber) {
      res.status(400).json({
        success: false,
        message: "Error: Invalid Input"
      })
    }

    const [rows, fields] = await connection.promise().query("SELECT * FROM application WHERE App_Acronym = ?", [App_Acronym])
    if (rows.length !== 0) {
      res.status(400).json({
        success: false,
        message: "Error: Application already exists"
      })
    }

    if (App_Rnumber < 0 || App_Rnumber % 1 !== 0) {
      res.status(400).json({
        success: false,
        message: "Error: Invalid Input"
      })
    }

    if (!App_startDate) {
      App_startDate = null
    }

    if (!App_endDate) {
      App_endDate = null
    }

    if (!App_permit_create) {
      App_permit_create = null
    }

    if (!App_permit_Open) {
      App_permit_Open = null
    }

    if (!App_permit_toDoList) {
      App_permit_toDoList = null
    }

    if (!App_permit_Doing) {
      App_permit_Doing = null
    }

    if (!App_permit_Done) {
      App_permit_Done = null
    }

    const response = await connection.promise().query("INSERT INTO application (App_Acronym, App_Description, App_Rnumber, App_startDate, App_endDate, App_permit_create, App_permit_Open, App_permit_toDoList, App_permit_Doing, App_permit_Done) VALUES (?,?,?,?,?,?,?,?,?,?)", [App_Acronym, App_Description, App_Rnumber, App_startDate, App_endDate, App_permit_create, App_permit_Open, App_permit_toDoList, App_permit_Doing, App_permit_Done])
    if (response[0].affectedRows === 0) {
      res.status(500).json({
        success: false,
        message: "Error: Failed to create application"
      })
    }

    res.status(200).json({
      success: true,
      message: "Application created successfully"
    })
  } catch (e) {
    console.log(e)
  }
}

//Update app => /updateApp/:App_Acronym
exports.updateApp = async (req, res, next) => {
  const App_Acronym = req.params.App_Acronym
  try {
    const [rows, fields] = await connection.promise().query("SELECT * FROM application WHERE App_Acronym = ?", [App_Acronym])
    if (rows.length === 0) {
      console.log(rows)
      res.status(404).json({
        success: false,
        message: "Error: Application does not exist"
      })
    }

    let query = "UPDATE application SET "
    let values = []
    if (req.body.App_Description) {
      query += "App_Description = ?, "
      values.push(req.body.App_Description)
    }
    if (req.body.App_startDate) {
      query += "App_startDate = ?, "
      values.push(req.body.App_startDate)
    }
    if (req.body.App_endDate) {
      query += "App_endDate = ?, "
      values.push(req.body.App_endDate)
    }
    if (req.body.App_permit_create) {
      query += "App_permit_create = ?, "
      values.push(req.body.App_permit_create)
    }
    if (req.body.App_permit_Open) {
      query += "App_permit_Open = ?, "
      values.push(req.body.App_permit_Open)
    }
    if (req.body.App_permit_toDoList) {
      query += "App_permit_toDoList = ?, "
      values.push(req.body.App_permit_toDoList)
    }
    if (req.body.App_permit_Doing) {
      query += "App_permit_Doing = ?, "
      values.push(req.body.App_permit_Doing)
    }
    if (req.body.App_permit_Done) {
      query += "App_permit_Done = ?, "
      values.push(req.body.App_permit_Done)
    }

    if (query === "UPDATE application SET ") {
      res.status(400).json({
        success: true,
        message: "Nothing updated"
      })
    } else {
      query = query.slice(0, -2)
      query += " WHERE App_Acronym = ?"
      values.push(App_Acronym)
    }

    const response = await connection.promise().execute(query, values)
    if (response[0].affectedRows === 0) {
      res.status(500).json({
        success: false,
        message: "Error: Failed to update application"
      })
    }

    res.status(200).json({
      success: true,
      message: "Application updated successfully"
    })
  } catch (e) {
    console.log(e)
  }
}

//Get appInfo => /appInfo/:App_Acronym
exports.getAppInfo = async (req, res, next) => {
  const App_Acronym = req.params.App_Acronym
  try {
    const [rows, fields] = await connection.promise().query("SELECT * FROM application WHERE App_Acronym = ?", [App_Acronym])
    if (rows.length === 0) {
      res.status(404).json({
        success: false,
        message: "Error: Application does not exist"
      })
    }
    // console.log(rows)

    res.status(200).json({
      success: true,
      data: rows
    })
  } catch (e) {
    console.log(e)
  }
}

//Get tasks by application => /getTasksApp/:App_Acronym
exports.getTasksApp = async (req, res, next) => {
  const App_Acronym = req.params.App_Acronym
  try {
    const [rows, fields] = await connection.promise().query("SELECT * FROM application WHERE App_Acronym = ?", [App_Acronym])
    if (rows.length === 0) {
      res.status(404).json({
        success: false,
        message: "Error: Application does not exist"
      })
    }

    const application = rows[0]
    const [rows2, fields2] = await connection.promise().query("SELECT * FROM task LEFT JOIN plan on `Task_plan` = `Plan_MVP_name` AND `Task_app_Acronym` = `Plan_app_Acronym` WHERE Task_app_Acronym = ?", [App_Acronym])
    if (rows2.length === 0) {
      res.status(404).json({
        success: false,
        message: "Error: No tasks found"
      })
    }

    res.status(200).json({
      success: true,
      data: rows2
    })
  } catch (e) {
    console.log(e)
  }
}

//Create Task => /createTask
exports.createTask = async (req, res, next) => {
  let { Task_name, Task_description, Task_notes, Task_plan, Task_app_Acronym } = req.body
  let user = req.user.username
  console.log("I am here")

  try {
    if (!Task_name || !Task_app_Acronym) {
      res.status(400).json({
        success: false,
        message: "Error: Invalid input"
      })
    }
    if (!Task_plan) {
      Task_plan = null
    }
    console.log(Task_app_Acronym)
    const [rows, fields] = await connection.promise().query("SELECT * FROM application WHERE App_Acronym = ?", [Task_app_Acronym])
    if (rows.length === 0) {
      res.status(404).json({
        success: false,
        message: "Error: Application does not exist"
      })
    }

    const application = rows[0]
    const Task_id = Task_app_Acronym + application.App_Rnumber

    Task_app_Acronym = application.App_Acronym
    const Task_state = "Open"
    const Task_creator = user
    const Task_owner = user
    const Task_createDate = new Date().toISOString().slice(0, 19).replace("T", " ")
    //@TODO make it use local timezone
    console.log(Task_createDate)

    if (!Task_notes) {
      Task_notes = Task_owner + " created " + Task_name + " on the " + Task_createDate + "\n"
    }

    const response = await connection.promise().query("INSERT INTO task (Task_name, Task_description, Task_notes, Task_id, Task_plan, Task_app_acronym, Task_state, Task_creator, Task_owner, Task_createDate) VALUES (?,?,?,?,?,?,?,?,?,?)", [Task_name, Task_description, Task_notes, Task_id, Task_plan, Task_app_Acronym, Task_state, Task_creator, Task_owner, Task_createDate])
    if (response[0].affectedRows === 0) {
      res.status(500).json({
        success: false,
        message: "Error: Failed to create task"
      })
    }

    const newApp_Rnumber = application.App_Rnumber + 1
    const response2 = await connection.promise().query("UPDATE application SET App_Rnumber = ? WHERE App_Acronym = ?", [newApp_Rnumber, Task_app_Acronym])
    if (response2.affectedRows === 0) {
      res.status(500).json({
        success: false,
        message: "Error: Incremental er404"
      })
    }

    res.status(200).json({
      success: true,
      message: "Task successfully created"
    })
  } catch (e) {
    console.log(e)
  }
}

//Get task => /getTaskInfo/:Task_id
exports.getTaskInfo = async (req, res, next) => {
  const Task_id = req.params.Task_id
  try {
    const [rows, fields] = await connection.promise().query("SELECT * FROM task WHERE Task_id = ?", [Task_id])
    if (rows.length === 0) {
      res.status(404).json({
        success: false,
        message: "Error: Task does not exist"
      })
    }

    res.status(200).json({
      success: true,
      data: rows
    })
  } catch (e) {
    console.log(e)
  }
}

//Update notes => /updateNotes/:Task_id
exports.updateNotes = async (req, res, next) => {
  const Task_id = req.params.Task_id
  try {
    const [rows, fields] = await connection.promise().query("SELECT * FROM task WHERE Task_id = ?", [Task_id])
    if (rows.length === 0) {
      res.status(404).json({
        success: false,
        message: "Error: Task does not exist"
      })
    }

    const validate = await validatePermit(rows[0].Task_app_Acronym, rows[0].Task_state, req.user.username)
    if (!validate) {
      res.status(403).json({
        success: false,
        message: "Error: Not authorised"
      })
    }

    let addedNotes
    if (!req.body.Task_notes) {
      res.status(200).json({
        success: true,
        message: "Nothing added"
      })
    } else {
      const dateNow = new Date().toISOString().slice(0, 19).replace("T", " ")
      addedNotes = req.body.Task_notes + "\n" + rows[0].Task_owner + " added on " + dateNow + "\n" + rows[0].Task_notes + "\n"

      const response = await connection.promise().query("UPDATE task SET Task_notes = ? WHERE Task_id = ?", [addedNotes, Task_id])
      if (response[0].affectedRows === 0) {
        res.status(500).json({
          success: false,
          message: "Error: Failed to update notes"
        })
      }

      res.status(200).json({
        success: true,
        message: "Notes updated successfully"
      })
    }
  } catch (e) {
    console.log(e)
  }
}

const validatePermit = async (App_Acronym, Task_state, user) => {
  try {
    const [rows, fields] = await connection.promise().query("SELECT * FROM application WHERE App_Acronym = ?", [App_Acronym])
    if (rows.length === 0) {
      // res.status(404).json({
      //   success: false,
      //   message: "Error: Application does not exist"
      // })
      console.log("Error: Application does not exist")
    }

    const application = rows[0]
    let permit_state
    switch (Task_state) {
      case "Open":
        permit_state = application.App_permit_Open
        break
      case "ToDo":
        permit_state = application.App_permit_toDoList
        break
      case "Doing":
        permit_state = application.App_permit_Doing
        break
      case "Done":
        permit_state = application.App_permit_Done
        break
      default:
        // res.status(400).json({
        //   success: false,
        //   message: "Error: Invalid task state"
        // })
        console.log("Error: Invalid task state")
    }

    if (permit_state === null || permit_state === undefined) {
      return false
    }

    const permit_list = permit_state.split(",")
    const [rows2, fields2] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [user])
    if (rows2.length === 0) {
      // res.status(404).json({
      //   success: false,
      //   message: "Error: User does not exist"
      // })
      console.log("Error: User does not exist")
    }

    const user_groups = rows2[0].grouplist.slice(1, -1).split(",")
    authorised = false
    for (let i = 0; i < user_groups.length; i++) {
      if (permit_list.includes(user_groups[i])) {
        authorised = true
        break
      }
    }

    if (!authorised) {
      return false
    }
    return true
  } catch (e) {
    console.log(e)
  }
}

//Promote task => /promoteTask/:Task_id
exports.promoteTask = async (req, res, next) => {
  const Task_id = req.params.Task_id
  try {
    const [rows, fields] = await connection.promise().query("SELECT * FROM task WHERE Task_id = ?", [Task_id])
    if (rows.length === 0) {
      res.status(404).json({
        success: false,
        message: "Error: Task does not exist"
      })
    }

    const validate = await validatePermit(rows[0].Task_app_Acronym, rows[0].Task_state, req.user.username)
    if (!validate) {
      res.status(403).json({
        success: false,
        message: "Error: Not authorised"
      })
      return
    }

    const Task_state = rows[0].Task_state
    if (Task_state === "Close") {
      res.status(404).json({
        success: false,
        meesage: "Error: You cannot promote a closed task"
      })
    }

    let nextState
    switch (Task_state) {
      case "Open":
        nextState = "ToDo"
        break
      case "ToDo":
        nextState = "Doing"
        break
      case "Doing":
        nextState = "Done"
        break
      case "Done":
        nextState = "Close"
        break
      default:
        nextState = "Close"
    }

    const Task_owner = req.user.username
    let Added_Task_notes
    if (req.body.Task_notes === undefined || null) {
      Added_Task_notes = Task_owner + " moved " + rows[0].Task_name + " from " + Task_state + " to " + nextState + "\n"
    } else {
      Added_Task_notes = req.body.Task_notes + "\n" + Task_owner + " moved " + rows[0].Task_name + " from " + Task_state + " to " + nextState + "\n"
    }

    const Task_notes = Added_Task_notes + "\n" + rows[0].Task_notes
    const response = await connection.promise().query("UPDATE task SET Task_notes = ?, Task_state = ?, Task_owner = ? WHERE Task_id = ?", [Task_notes, nextState, Task_owner, Task_id])
    if (response[0].affectedRows === 0) {
      res.status(500).json({
        success: false,
        message: "Error: Failed to promote task"
      })
    }
    res.status(200).json({
      success: true,
      message: "Task promoted successfully"
    })

    if (Task_state === "Doing" && nextState === "Done") {
      sendEmail(rows[0].Task_name, Task_owner, rows[0].Task_app_Acronym)
    }
  } catch (e) {
    console.log(e)
  }
}

async function sendEmail(taskName, taskOwner, Task_app_Acronym) {
  const [rows, fields] = await connection.promise().query("SELECT * FROM application WHERE App_Acronym = ?", [Task_app_Acronym])
  const group = rows[0].App_permit_Done

  const [rows2, fields2] = await connection.promise().query("SELECT * FROM user")
  const users = rows2
  let emails = []
  for (let i = 0; i < users.length; i++) {
    const user = users[i]
    const user_groups = user.grouplist.slice(1, -1).split(",")
    if (user_groups.includes(group)) {
      if (user.email !== null && user.email !== undefined) {
        emails.push(user.email)
        console.log(emails)
      }
    }
  }

  const transport = nodemailer.createTransport({
    host: "sandbox.smtp.mailtrap.io",
    port: 2525,
    auth: {
      user: "8a2a19e013f247",
      pass: "bfab472441df5b"
    }
  })

  const mailOptions = {
    from: `${process.env.SMTP_FROM_NAME} <${process.env.SMTP_FROM_EMAIL}>`,
    to: emails,
    subject: `Task promotion`,
    text: `${taskName} has been promoted to "Done" by ${taskOwner}.`
  }

  try {
    await transport.sendMail(mailOptions)
    console.log("Email sent successfully")
  } catch (e) {
    console.log("Failed to send email:", e)
  }
}

//Reject Task from Done -> Doing => /rejectTask/:Task_id
exports.rejectTask = async (req, res, next) => {
  const Task_id = req.params.Task_id
  try {
    const [rows, fields] = await connection.promise().query("SELECT * FROM task WHERE Task_id = ?", [Task_id])
    if (rows[0].length === 0) {
      res.status(404).json({
        success: false,
        message: "Error: Task does not exist"
      })
    }

    const validate = await validatePermit(rows[0].Task_app_Acronym, rows[0].Task_state, req.user.username)
    if (!validate) {
      res.status(403).json({
        success: false,
        message: "Error: Not authorised"
      })
    }

    const Task_state = rows[0].Task_state
    if (Task_state !== "Done") {
      res.status(404).json({
        success: false,
        message: "Error: Cannot reject a task not in Done"
      })
    }

    const nextState = "Doing"
    const Task_owner = req.user.username
    let Added_Task_notes
    if (req.body.Task_notes === undefined || null) {
      Added_Task_notes = Task_owner + " moved " + rows[0].Task_name + " from " + Task_state + " to " + nextState + "\n"
    } else {
      Added_Task_notes = req.body.Task_notes + "\n" + Task_owner + " moved " + rows[0].Task_name + " from " + Task_state + " to " + nextState + "\n"
    }

    const Task_notes = Added_Task_notes + rows[0].Task_notes
    let Task_plan
    if (req.body.Task_plan === undefined || JSON.stringify(req.body.Task_plan === "{}") || "") {
      Task_plan = null
    } else {
      Task_plan = req.body.Task_plan
    }

    const response = await connection.promise().query("UPDATE task SET Task_notes = ?, Task_state = ?, Task_owner = ?, Task_plan = ? WHERE Task_id = ?", [Task_notes, nextState, Task_owner, Task_plan, Task_id])
    if (response[0].affectedRows === 0) {
      res.status(500).json({
        success: false,
        message: "Error: Failed to reject task"
      })
    }

    res.status(200).json({
      success: true,
      message: "Task rejected successfully"
    })
  } catch (e) {
    console.log(e)
    res.status(404).json({
      success: false,
      message: "Error: Exception error"
    })
  }
}

//Return task from Doing -> ToDo => /returnTask/:Task_id
exports.returnTask = async (req, res, next) => {
  const Task_id = req.params.Task_id
  try {
    const [rows, fields] = await connection.promise().query("SELECT * FROM task WHERE Task_id = ?", [Task_id])
    if (rows.length === 0) {
      res.status(404).json({
        success: false,
        message: "Error: Task does not exist"
      })
    }

    const validate = await validatePermit(rows[0].Task_app_Acronym, rows[0].Task_state, req.user.username)
    if (!validate) {
      res.status(403).json({
        success: false,
        message: "Error: Not authorised"
      })
    }

    const Task_state = rows[0].Task_state
    if (Task_state !== "Doing") {
      res.status(404).json({
        success: false,
        message: "Error: Cannot return a task not in Doing"
      })
    }

    const nextState = "ToDo"
    const Task_owner = req.user.username
    let Added_Task_notes
    if (req.body.Task_notes === undefined || null) {
      Added_Task_notes = Task_owner + " moved " + rows[0].Task_name + " from " + Task_state + " to " + nextState + "\n"
    } else {
      Added_Task_notes = req.body.Task_notes + "\n" + Task_owner + " moved " + rows[0].Task_name + " from " + Task_state + " to " + nextState + "\n"
    }

    const Task_notes = Added_Task_notes + rows[0].Task_notes
    const response = await connection.promise().execute("UPDATE task SET Task_notes = ?, Task_state = ?, Task_owner = ? WHERE Task_id = ?", [Task_notes, nextState, Task_owner, Task_id])
    if (response[0].affectedRows === 0) {
      res.status(500).json({
        success: false,
        message: "Error: Failed to return task"
      })
    }

    res.status(200).json({
      success: true,
      message: "Task returned successfully"
    })
  } catch (e) {
    console.log(e)
  }
}

//Get plan => /getPlan
exports.getPlan = async (req, res, next) => {
  const { Plan_app_Acronym, Plan_MVP_name } = req.body
  try {
    const [rows, fields] = await connection.promise().query("SELECT * FROM plan WHERE Plan_app_Acronym = ? AND Plan_MVP_name = ?", [Plan_app_Acronym, Plan_MVP_name])
    if (rows.length === 0) {
      res.status(404).json({
        success: false,
        message: "Error: Plan does not exist"
      })
    }

    res.status(200).json({
      success: true,
      data: rows[0]
    })
  } catch (e) {
    console.log(e)
  }
}

//Get Plan by app => /getPlanApp/:App_Acronym
exports.getPlanApp = async (req, res, next) => {
  const App_Acronym = req.params.App_Acronym
  try {
    const [rows, fields] = await connection.promise().query("SELECT * FROM application WHERE App_Acronym = ?", [App_Acronym])
    if (rows.length === 0) {
      res.status(404).json({
        success: false,
        message: "Error: Application does not exist"
      })
    }

    const application = rows[0]
    const [rows2, fields2] = await connection.promise().query("SELECT * FROM plan WHERE Plan_app_Acronym = ?", [App_Acronym])
    if (rows2.length === 0) {
      res.status(404).json({
        success: false,
        message: "Error: No plans found"
      })
    }

    res.status(200).json({
      success: true,
      data: rows2
    })
  } catch (e) {
    console.log(e)
  }
}

//Create plan => /createPlan
exports.createPlan = async (req, res, next) => {
  const { Plan_app_Acronym, Plan_MVP_name } = req.body
  try {
    const [rows, fields] = await connection.promise().query("SELECT * FROM plan WHERE Plan_app_Acronym = ? AND Plan_MVP_name = ?", [Plan_app_Acronym, Plan_MVP_name])
    if (rows.length !== 0) {
      res.status(404).json({
        success: false,
        message: "Error: Plan already exist"
      })
    }

    const [rows2, fields2] = await connection.promise().query("SELECT * FROM application WHERE App_Acronym = ?", [Plan_app_Acronym])
    if (rows2.length === 0) {
      res.status(404).json({
        success: false,
        message: "Error: Application does not exist"
      })
    }

    if (!Plan_app_Acronym || !Plan_MVP_name) {
      res.status(404).json({
        success: false,
        message: "Error: Invalid input"
      })
    }

    let { Plan_startDate, Plan_endDate, Plan_color } = req.body
    if (!Plan_startDate) {
      Plan_startDate = null
    }
    if (!Plan_endDate) {
      Plan_endDate = null
    }

    const response = await connection.promise().query("INSERT INTO plan (Plan_app_Acronym, Plan_MVP_name, Plan_startDate, Plan_endDate, Plan_color) VALUES (?,?,?,?,?)", [Plan_app_Acronym, Plan_MVP_name, Plan_startDate, Plan_endDate, Plan_color])
    if (response[0].affectedRows === 0) {
      res.status(500).json({
        success: false,
        message: "Error: Failed to create plan"
      })
    }

    res.status(200).json({
      success: true,
      message: "Plan created successfully"
    })
  } catch (e) {
    console.log(e)
  }
}

//Update plan => /updatePlan
exports.updatePlan = async (req, res, next) => {
  const { Plan_app_Acronym, Plan_MVP_name } = req.body
  try {
    const [rows, fields] = await connection.promise().query("SELECT * FROM plan WHERE Plan_app_Acronym = ? AND Plan_MVP_name = ?", [Plan_app_Acronym, Plan_MVP_name])
    if (rows.length === 0) {
      res.status(404).json({
        success: false,
        message: "Error: Plan does not exist"
      })
    }

    const [rows2, fields2] = await connection.promise().query("SELECT * FROM application WHERE App_Acronym = ?", [Plan_app_Acronym])
    if (rows2.length === 0) {
      res.status(404).json({
        success: false,
        message: "Error: Application does not exist"
      })
    }

    if (!Plan_app_Acronym || !Plan_MVP_name) {
      res.status(404).json({
        success: false,
        message: "Error: Invalid input"
      })
    }

    let query = "UPDATE plan SET "
    let params = []
    if (req.body.Plan_startDate) {
      query += "Plan_startDate = ?, "
      params.push(req.body.Plan_startDate)
    }
    if (req.body.Plan_endDate) {
      query += "Plan_endDate = ?, "
      params.push(req.body.Plan_endDate)
    }

    if (query === "UPDATE plan SET ") {
      console.log(query)
      res.status(200).json({
        success: true,
        message: "Nothing updated"
      })
    } else {
      query = query.slice(0, -2)
      query += " WHERE Plan_app_Acronym = ? AND Plan_MVP_name = ?"
      params.push(Plan_app_Acronym)
      params.push(Plan_MVP_name)
    }

    const response = await connection.promise().execute(query, params)
    if (response[0].affectedRows === 0) {
      res.status(500).json({
        success: false,
        message: "Error: Failed to update plan"
      })
    }

    res.status(200).json({
      success: true,
      message: "Plan updated successfully"
    })
  } catch (e) {
    console.log(e)
  }
}

//Assign Task to plan => /assignTaskPlan/:Task_id
exports.assignTaskPlan = async (req, res, next) => {
  const { Plan_app_Acronym, Plan_MVP_name } = req.body
  const Task_id = req.params.Task_id
  try {
    const [rows, fields] = await connection.promise().query("SELECT * FROM plan WHERE Plan_app_Acronym = ? AND Plan_MVP_name = ?", [Plan_app_Acronym, Plan_MVP_name])
    if (rows.length === 0) {
      res.status(404).json({
        success: false,
        message: "Error: Plan does not exist"
      })
    }

    const [rows2, fields2] = await connection.promise().query("SELECT * FROM task WHERE Task_id = ?", [Task_id])
    if (rows2.length === 0) {
      res.status(404).json({
        success: false,
        message: "Error: Task does not exist"
      })
    }

    const [rows3, fields3] = await connection.promise().query("SELECT * FROM application WHERE App_Acronym = ?", [Plan_app_Acronym])
    if (rows3.length === 0) {
      res.status(404).json({
        success: false,
        message: "Error: Application does not exist"
      })
    }

    if (!Plan_app_Acronym || !Plan_MVP_name) {
      npm
      res.status(404).json({
        success: false,
        message: "Error: Invalid input"
      })
    }

    const Task_owner = req.user.username
    let Added_Task_notes
    if (req.body.Task_notes === undefined || null) {
      Added_Task_notes = Task_owner + " assigned " + rows2.Task_name + " to " + Plan_MVP_name + "\n"
    } else {
      Added_Task_notes = req.body.Task_notes + "\n" + Task_owner + " assigned " + rows2[0].Task_name + " to " + Plan_MVP_name + "\n"
    }

    const Task_notes = Added_Task_notes + rows2[0].Task_notes
    const response = await connection.promise().execute("UPDATE task SET Task_notes = ?, Task_plan = ?, Task_owner = ? WHERE Task_id =?", [Task_notes, Plan_MVP_name, Task_owner, Task_id])
    if (response[0].affectedRows === 0) {
      res.status(500).json({
        success: false,
        message: "Error: Failed to assign plan to task"
      })
    }

    res.status(200).json({
      success: true,
      message: "Plan assigned to task successfully"
    })
  } catch (e) {
    console.log(e)
  }
}
