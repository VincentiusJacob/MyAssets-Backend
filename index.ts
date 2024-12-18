import { User } from "@supabase/supabase-js";
declare global {
  namespace Express {
    interface Session {
      user?: User;
    }
  }
}
import express, { Request, Response } from "express";
import path from "path";
import bodyParser from "body-parser";
import cors from "cors";
import session from "express-session";
import bcrypt from "bcrypt";
import passport from "passport";
import dotenv from "dotenv";
import multer from "multer";
import { supabase } from "./supabaseClient";
import { AuthResponse } from "@supabase/supabase-js";

dotenv.config();

const app = express();
const port = 5000;
const saltRounds = 10;

// Middleware setup

app.use(
  cors({
    origin: "https://myassets-gamma.vercel.app",
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    name: "MyAssetsCookie",
    secret: process.env.SESSION_SECRET as string,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true, maxAge: 24 * 60 * 60 * 1000 },
  })
);

app.use((req, res, next) => {
  console.log("Session Data:", req.session);
  next();
});

app.use(passport.initialize());
app.use(passport.session());

const storage = multer.memoryStorage();
const upload = multer({ storage });

// Authentication and Authorization

app.post("/auth/register", async (req: Request, res: Response) => {
  const { email, password, username } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const { data, error: authError } = await supabase.auth.signUp({
      email,
      password,
    });

    if (authError) return res.status(400).json({ error: authError.message });

    const user = data?.user;

    if (!user) return res.status(400).json({ error: "User creation failed." });

    const { error: dbError } = await supabase.from("users").insert([
      {
        username,
        email,
        password: hashedPassword,
        created_at: new Date(),
        updated_at: new Date(),
      },
    ]);

    if (dbError) return res.status(400).json({ error: dbError.message });

    res.status(200).json({ user, username });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/auth/login", async (req: Request, res: Response) => {
  const { email, password } = req.body;

  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .single();

    if (error || !user) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    const isPasswordMatch = await bcrypt.compare(password, user.password);

    if (!isPasswordMatch) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    (req.session as { user?: User }).user = user;

    res.status(200).json({ user });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/auth/logout", async (req: Request, res: Response) => {
  try {
    await supabase.auth.signOut();

    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ error: "Failed to logout." });
      }

      res.clearCookie("MyAssetsCookie");
      res.status(200).json({ message: "Logged out successfully." });
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

passport.serializeUser((user: any, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id: string, done) => {
  try {
    const { data, error } = await supabase
      .from("users")
      .select("*")
      .eq("user_id", id)
      .single();

    if (error) {
      return done(error, null);
    }

    done(null, data);
  } catch (err) {
    done(err, null);
  }
});

// Routes

app.put("/updateProfile", async (req, res) => {
  const { data: requestData } = req.body;

  if (!requestData.email) {
    return res.status(400).json({ message: "Email is required" });
  }

  const formattedDateOfBirth = requestData.dateofbirth || null;

  try {
    const { data, error } = await supabase
      .from("users")
      .select("user_id")
      .eq("email", requestData.email)
      .single();

    if (error) {
      console.log("error getting userid");
    }

    const userId = data?.user_id;

    const { error: dbError } = await supabase.from("userprofiles").upsert(
      {
        user_id: userId,
        firstname: requestData.firstname || null,
        lastname: requestData.lastname || null,
        dateofbirth: formattedDateOfBirth,
        address: requestData.address || null,
        phonenumber: requestData.phonenumber || null,
        profilepicture: requestData.profilepicture || null,
      },
      { onConflict: "userid" }
    );

    if (dbError) {
      console.error("Database error:", dbError);
      return res.status(500).json({ message: "Failed to update profile data" });
    }

    res.status(200).json({ message: "Profile updated successfully" });
  } catch (err: any) {
    console.error("Error updating profile:", err);
    res
      .status(500)
      .json({ message: "Failed to update profile", error: err.message });
  }
});

app.post(
  "/uploadProfilePicture",
  upload.single("profilepicture"),
  async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ message: "No file uploaded" });
    }

    try {
      const { data, error } = await supabase.storage
        .from("profile-pictures")
        .upload(`profilepictures/${req.file.filename}`, req.file.buffer);

      if (error) {
        return res
          .status(500)
          .json({ message: "Upload failed", error: error.message });
      }

      const publicUrl = supabase.storage
        .from("profile-pictures")
        .getPublicUrl(`profilepictures/${req.file.filename}`);

      res.json({ url: publicUrl.data.publicUrl });
    } catch (err: any) {
      console.error("Error uploading file:", err);
      res
        .status(500)
        .json({ message: "Error uploading file", error: err.message });
    }
  }
);

app.get("/getProfile/:email", async (req, res) => {
  const { email } = req.params;

  try {
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .single();

    if (userError) {
      console.error("Error finding user:", userError);
      return res.status(404).json({ message: "User not found" });
    }

    const userId = user.user_id;

    const { data: profile, error: profileError } = await supabase
      .from("userprofiles")
      .select("*")
      .eq("user_id", userId)
      .single();

    if (profileError && profileError.code !== "PGRST116") {
      console.error("Error finding profile:", profileError);
      return res.status(500).json({ message: "Failed to get profile data" });
    }

    if (profile) {
      return res.status(200).json(profile);
    } else {
      const { data: newProfile, error: insertError } = await supabase
        .from("userprofiles")
        .insert([{ user_id: userId }])
        .single();

      if (insertError) {
        console.error("Error inserting new profile:", insertError);
        return res.status(500).json({ message: "Failed to create profile" });
      }

      console.log("New user profile created:", newProfile);
      return res.status(200).json(newProfile);
    }
  } catch (err: any) {
    console.error("Failed to get profile data:", err);
    return res
      .status(500)
      .json({ message: "Failed to get profile data", error: err.message });
  }
});

app.post("/newTransaction", async (req, res) => {
  const { username, title, amount, category, description, type } = req.body;
  console.log("User is:", username);
  console.log("req: ", req.body);

  try {
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("*")
      .eq("username", username)
      .single();

    if (userError || !user) {
      console.log("User not found");
      return res.status(401).json({ message: "User not found" });
    }

    const userId = user.user_id;
    console.log("User ID:", userId);

    const currentDate = new Date().toISOString().split("T")[0];

    const { error: insertError } = await supabase.from("transactions").insert([
      {
        user_id: userId,
        title,
        amount,
        date: currentDate,
        category,
        description,
        type,
      },
    ]);

    if (insertError) {
      console.error("Error inserting transaction:", insertError);
      return res.status(500).json({
        message: "Failed to create transaction",
        error: insertError.message,
      });
    }

    return res.status(200).json({ message: "Successful transaction" });
  } catch (err: any) {
    console.error("Error processing transaction:", err.message);
    return res
      .status(500)
      .json({ message: "Failed to create transaction", error: err.message });
  }
});

app.get("/getTransaction/:username", async (req, res) => {
  const { username } = req.params;

  console.log("Username:", username);

  try {
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("user_id")
      .eq("username", username)
      .single();

    if (userError || !user) {
      console.error("User not found");
      return res.status(404).json({ message: "User not found" });
    }

    const userId = user.user_id;
    console.log("Current user ID:", userId);

    const { data: transactions, error: transactionError } = await supabase
      .from("transactions")
      .select("title, amount, date, category, description")
      .eq("user_id", userId);

    if (transactionError) {
      console.error("Error fetching transactions:", transactionError);
      return res
        .status(500)
        .json({ message: "Failed to retrieve transactions" });
    }

    console.log("Transactions:", transactions);
    return res.status(200).json(transactions);
  } catch (err: any) {
    console.error("Error processing transaction fetch:", err.message);
    return res
      .status(500)
      .json({ message: "Failed to retrieve transactions", error: err.message });
  }
});

app.get("/api/expenseData/:username", async (req, res) => {
  const { username } = req.params;

  try {
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("user_id")
      .eq("username", username)
      .single();

    if (userError || !user) {
      console.error("User not found");
      return res.status(404).json({ message: "User not found" });
    }

    const userId = user.user_id;

    const { data: expenses, error: expenseError } = await supabase
      .from("transactions")
      .select("*")
      .eq("category", "Expense")
      .eq("user_id", userId);

    if (expenseError) {
      console.error("Error fetching expense data:", expenseError);
      return res
        .status(500)
        .json({ message: "Failed to retrieve expense data" });
    }

    console.log("Expenses:", expenses);
    return res.status(200).json(expenses);
  } catch (err: any) {
    console.error("Error processing expense fetch:", err.message);
    return res
      .status(500)
      .json({ message: "Failed to retrieve expense data", error: err.message });
  }
});

app.get("/api/netWorth/:username", async (req, res) => {
  const { username } = req.params;

  try {
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("user_id")
      .eq("username", username)
      .single();

    if (userError || !user) {
      console.error("User not found");
      return res.status(404).json({ message: "User not found" });
    }

    const userId = user.user_id;

    const monthList = Array.from({ length: 12 }, (_, i) => {
      const date = new Date();
      date.setMonth(i);
      date.setDate(1);
      return date.toISOString().slice(0, 7);
    });

    const { data: transactions, error: transactionsError } = await supabase
      .from("transactions")
      .select("category, date, amount")
      .eq("user_id", userId);

    if (transactionsError) {
      console.error("Error fetching transactions:", transactionsError);
      return res
        .status(500)
        .json({ message: "Failed to retrieve transactions" });
    }

    const { data: outstanding, error: outstandingError } = await supabase
      .from("outstanding_payments")
      .select("created_at, amount_due, amount_paid")
      .eq("user_id", userId);

    if (outstandingError) {
      console.error("Error fetching outstanding payments:", outstandingError);
      return res
        .status(500)
        .json({ message: "Failed to retrieve outstanding payments" });
    }

    const assets = transactions
      .filter((t) => ["Income", "Savings", "Investment"].includes(t.category))
      .reduce((acc, t) => {
        const month = new Date(t.date).toISOString().slice(0, 7);
        acc[month] = (acc[month] || 0) + t.amount;
        return acc;
      }, {} as { [month: string]: number });

    const expenses = transactions
      .filter((t) => t.category === "Expense")
      .reduce((acc, t) => {
        const month = new Date(t.date).toISOString().slice(0, 7);
        acc[month] = (acc[month] || 0) + t.amount;
        return acc;
      }, {} as { [month: string]: number });

    const outstandingPayments = outstanding.reduce((acc, o) => {
      const month = new Date(o.created_at).toISOString().slice(0, 7);
      acc[month] = (acc[month] || 0) + (o.amount_due - o.amount_paid);
      return acc;
    }, {} as { [month: string]: number });

    const netWorthByMonth = monthList.map((month) => {
      const totalAssets = assets[month] || 0;
      const totalExpenses = expenses[month] || 0;
      const totalOutstanding = outstandingPayments[month] || 0;

      const netWorth = totalAssets - (totalExpenses + totalOutstanding);

      return { month, netWorth };
    });

    res.status(200).json(netWorthByMonth);
  } catch (err: any) {
    console.error("Error processing net worth calculation:", err.message);
    res
      .status(500)
      .json({ message: "Failed to retrieve net worth", error: err.message });
  }
});

app.get("/api/overview/:username", async (req, res) => {
  const { username } = req.params;

  console.log("username: ", username);

  try {
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("user_id")
      .eq("username", username)
      .single();

    if (userError) {
      console.error("Error fetching user:", userError.message);
      return res.status(500).send("Error fetching user");
    }

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const userid = user.user_id;

    const { data, error } = await supabase
      .from("transactions")
      .select(
        `
        date,
        category,
        amount
      `
      )
      .eq("user_id", userid);

    if (error) {
      console.error("Error fetching transactions data:", error.message);
      return res.status(500).send("Server error");
    }

    if (!data || data.length === 0) {
      return res.status(404).json({ message: "No data found for this user" });
    }

    type Overview = {
      [key: string]: {
        income: number;
        savings: number;
        investment: number;
        expense: number;
      };
    };

    const overview = data.reduce((acc: Overview, transaction) => {
      const month = new Date(transaction.date).toISOString().slice(0, 7);
      const category = transaction.category;
      const amount = transaction.amount;

      if (!acc[month]) {
        acc[month] = {
          income: 0,
          savings: 0,
          investment: 0,
          expense: 0,
        };
      }

      if (category === "Income") {
        acc[month].income += amount;
      } else if (category === "Savings") {
        acc[month].savings += amount;
      } else if (category === "Investment") {
        acc[month].investment += amount;
      } else if (category === "Expense") {
        acc[month].expense += amount;
      }

      return acc;
    }, {});

    const result = Object.keys(overview).map((month) => ({
      month,
      income: overview[month].income,
      savings: overview[month].savings,
      investment: overview[month].investment,
      expense: overview[month].expense,
    }));

    res.json(result);
  } catch (error) {
    console.error("Unexpected error:", error);
    res.status(500).send("Server error");
  }
});

app.get("/api/incomeTrends/:username", async (req, res) => {
  const { username } = req.params;

  try {
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("user_id")
      .eq("username", username)
      .single();

    if (userError) {
      console.error("Error fetching user:", userError.message);
      return res.status(500).send("Error fetching user");
    }

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const userid = user.user_id;

    const { data, error } = await supabase
      .from("transactions")
      .select(
        `
        date,
        category,
        amount
      `
      )
      .eq("user_id", userid);

    if (error) {
      console.error("Error fetching transactions data:", error.message);
      return res.status(500).send("Server error");
    }

    if (!data || data.length === 0) {
      return res.status(404).json({ message: "No data found for this user" });
    }

    const incomeTrends = data.reduce((acc: any, transaction) => {
      const month = new Date(transaction.date).toISOString().slice(0, 7);
      const category = transaction.category;
      const amount = transaction.amount;

      if (!acc[month]) {
        acc[month] = {
          income: 0,
          savings: 0,
          investment: 0,
        };
      }

      if (category === "Income") {
        acc[month].income += amount;
      } else if (category === "Savings") {
        acc[month].savings += amount;
      } else if (category === "Investment") {
        acc[month].investment += amount;
      }

      return acc;
    }, {});

    const result = Object.keys(incomeTrends).map((month) => ({
      month,
      income: incomeTrends[month].income,
      savings: incomeTrends[month].savings,
      investment: incomeTrends[month].investment,
    }));

    res.json(result);
  } catch (error) {
    console.error("Unexpected error:", error);
    res.status(500).send("Server error");
  }
});

app.get("/api/expense/:username", async (req, res) => {
  const { username } = req.params;

  try {
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("user_id")
      .eq("username", username)
      .single();

    if (userError) {
      console.error("Error fetching user:", userError.message);
      return res.status(500).send("Error fetching user");
    }

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const userid = user.user_id;

    const { data, error } = await supabase
      .from("transactions")
      .select("amount")
      .eq("category", "Expense")
      .eq("user_id", userid);

    if (error) {
      console.error("Error fetching transactions data:", error.message);
      return res.status(500).send("Error fetching transactions data");
    }

    if (!data || data.length === 0) {
      return res.status(404).json({ message: "No expenses found" });
    }

    let totalExpense = 0;
    data.forEach((transaction) => {
      totalExpense += parseFloat(transaction.amount);
    });

    console.log("Total expense: ", totalExpense);
    res.status(200).json(totalExpense);
  } catch (err: any) {
    console.error("Unexpected error:", err.message);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/balance/:username", async (req, res) => {
  const { username } = req.params;

  try {
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("user_id")
      .eq("username", username)
      .single();

    if (userError) {
      console.error("Error fetching user:", userError.message);
      return res.status(500).send("Error fetching user");
    }

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const userid = user.user_id;

    const { data, error } = await supabase
      .from("transactions")
      .select("amount, category")
      .eq("user_id", userid);

    if (error) {
      console.error("Error fetching transactions data:", error.message);
      return res.status(500).send("Error fetching transactions data");
    }

    if (!data || data.length === 0) {
      return res.status(404).json({ message: "No transactions found" });
    }

    let totalBalance = 0;
    data.forEach((transaction) => {
      if (transaction.category === "Income") {
        totalBalance += parseFloat(transaction.amount);
      } else if (
        transaction.category === "Savings" ||
        transaction.category === "Investment"
      ) {
        totalBalance -= parseFloat(transaction.amount);
      }
    });

    res.status(200).json({ totalBalance: totalBalance });
  } catch (err: any) {
    console.error("Unexpected error:", err.message);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/savings/:username", async (req, res) => {
  const { username } = req.params;

  try {
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("user_id")
      .eq("username", username)
      .single();

    if (userError) {
      console.error("Error fetching user:", userError.message);
      return res.status(500).send("Error fetching user");
    }

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const userid = user.user_id;

    const { data, error } = await supabase
      .from("transactions")
      .select("amount")
      .eq("category", "Savings")
      .eq("user_id", userid);

    if (error) {
      console.error("Error fetching savings data:", error.message);
      return res.status(500).send("Error fetching savings data");
    }

    if (!data || data.length === 0) {
      return res.status(404).json({ message: "No savings found" });
    }

    let totalSavings = 0;
    data.forEach((transaction) => {
      totalSavings += parseFloat(transaction.amount);
    });

    res.status(200).json(totalSavings);
  } catch (err: any) {
    console.error("Unexpected error:", err.message);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/invest/:username", async (req, res) => {
  const { username } = req.params;

  try {
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("user_id")
      .eq("username", username)
      .single();

    if (userError) {
      console.error("Error fetching user:", userError.message);
      return res.status(500).send("Error fetching user");
    }

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const userid = user.user_id;

    const { data, error } = await supabase
      .from("transactions")
      .select("amount")
      .eq("category", "Investment")
      .eq("user_id", userid);

    if (error) {
      console.error("Error fetching investment data:", error.message);
      return res.status(500).send("Error fetching investment data");
    }

    if (!data || data.length === 0) {
      return res.status(404).json({ message: "No investments found" });
    }

    let totalInvest = 0;
    data.forEach((transaction) => {
      totalInvest += parseFloat(transaction.amount);
    });

    console.log("total invest: ", totalInvest);
    res.status(200).json(totalInvest);
  } catch (err: any) {
    console.error("Unexpected error:", err.message);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/growthIncome/:username", async (req, res) => {
  const { username } = req.params;

  try {
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("user_id")
      .eq("username", username)
      .single();

    if (userError) {
      console.error("Error fetching user:", userError.message);
      return res.status(500).send("Error fetching user");
    }

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const userid = user.user_id;

    const { data, error } = await supabase
      .from("transactions")
      .select("date, category, amount")
      .eq("user_id", userid);

    if (error) {
      console.error("Error fetching growth income data:", error.message);
      return res.status(500).send("Error fetching growth income data");
    }

    const months = [
      "Jan",
      "Feb",
      "Mar",
      "Apr",
      "May",
      "Jun",
      "Jul",
      "Aug",
      "Sep",
      "Oct",
      "Nov",
      "Dec",
    ];

    const monthlyIncome = months.map((month) => {
      const monthData = data.filter((row) => {
        const rowMonth = new Date(row.date).toLocaleString("en-US", {
          month: "short",
        });
        return rowMonth.toLowerCase() === month.toLowerCase();
      });

      const totalIncome = monthData.reduce((acc, row) => {
        if (row.category === "Income") acc += parseFloat(row.amount);
        if (row.category === "Savings") acc -= parseFloat(row.amount);
        if (row.category === "Investment") acc -= parseFloat(row.amount);
        return acc;
      }, 0);

      return {
        month: month,
        totalIncome: totalIncome > 0 ? totalIncome : 0,
      };
    });

    res.json(monthlyIncome);
  } catch (err: any) {
    console.error("Unexpected error:", err.message);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/spendingData/:username", async (req, res) => {
  const { username } = req.params;

  try {
    // Fetch the user ID from Supabase
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("user_id")
      .eq("username", username)
      .single();

    if (userError) {
      console.error("Error fetching user:", userError.message);
      return res.status(500).send("Error fetching user");
    }

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const userid = user.user_id;

    const { data, error } = await supabase
      .from("transactions")
      .select("date, category, amount")
      .eq("user_id", userid)
      .eq("category", "Expense");

    if (error) {
      console.error("Error fetching spending data:", error.message);
      return res.status(500).send("Error fetching spending data");
    }

    const months = [
      "Jan",
      "Feb",
      "Mar",
      "Apr",
      "May",
      "Jun",
      "Jul",
      "Aug",
      "Sep",
      "Oct",
      "Nov",
      "Dec",
    ];

    const monthlySpending = months.map((month) => {
      const monthData = data.filter((row) => {
        const rowMonth = new Date(row.date).toLocaleString("en-US", {
          month: "short",
        });
        return rowMonth.toLowerCase() === month.toLowerCase();
      });

      const totalSpending = monthData.reduce((acc, row) => {
        return acc + parseFloat(row.amount);
      }, 0);

      return {
        month: month,
        totalSpending: totalSpending > 0 ? totalSpending : 0,
      };
    });

    res.json(monthlySpending);
  } catch (err: any) {
    console.error("Unexpected error:", err.message);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/investmentData/:username", async (req, res) => {
  const { username } = req.params;

  try {
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("user_id")
      .eq("username", username)
      .single();

    if (userError) {
      console.error("Error fetching user:", userError.message);
      return res.status(500).send("Error fetching user");
    }

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const userid = user.user_id;

    const { data, error } = await supabase
      .from("transactions")
      .select("type, amount")
      .eq("category", "Investment")
      .eq("user_id", userid);

    if (error) {
      console.error("Error fetching investment data:", error.message);
      return res.status(500).send("Error fetching investment data");
    }

    const investmentCount = data.reduce((acc: any, row) => {
      if (acc[row.type]) {
        acc[row.type] += 1;
      } else {
        acc[row.type] = 1;
      }
      return acc;
    }, {});

    const result = Object.keys(investmentCount).map((key: any) => ({
      type: key,
      count: investmentCount[key],
    }));

    res.json(result);
  } catch (err: any) {
    console.error("Unexpected error:", err.message);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/newOutstandingPayment", async (req, res) => {
  const { username, title, amount, description } = req.body;

  try {
    // Step 1: Fetch the user ID from Supabase
    const { data: userData, error: userError } = await supabase
      .from("users")
      .select("id")
      .eq("username", username)
      .single(); // Use single() since we're expecting one result

    if (userError) {
      console.error("Error fetching user:", userError.message);
      return res.status(404).json({ error: "User not found" });
    }

    const userId = userData.id;
    console.log("User ID:", userId);

    const { data: existingPaymentData, error: paymentError } = await supabase
      .from("outstanding_payments")
      .select("*")
      .eq("user_id", userId)
      .eq("payment_name", title)
      .single();

    if (paymentError) {
      console.error("Error checking payment:", paymentError.message);
      return res.status(500).json({ error: "Database error" });
    }

    if (existingPaymentData) {
      const currentAmountPaid = parseFloat(existingPaymentData.amount_paid);
      const newAmountPaid = (currentAmountPaid + parseFloat(amount)).toFixed(2);

      console.log("Current amount paid:", currentAmountPaid);
      console.log("New amount to be updated:", newAmountPaid);

      const { error: updateError } = await supabase
        .from("outstanding_payments")
        .update({ amount_paid: newAmountPaid })
        .eq("user_id", userId)
        .eq("payment_name", title);

      if (updateError) {
        console.error("Error updating payment:", updateError.message);
        return res.status(500).json({ error: "Error updating payment" });
      }

      return res.status(200).json({ message: "Payment updated successfully" });
    } else {
      const { error: insertError } = await supabase
        .from("outstanding_payments")
        .insert([
          {
            user_id: userId,
            payment_name: title,
            amount_due: amount,
            status: "Pending",
            description: description,
            amount_paid: 0,
          },
        ]);

      if (insertError) {
        console.error("Error inserting payment:", insertError.message);
        return res.status(500).json({ error: "Error creating payment" });
      }

      return res.status(200).json({ message: "Payment added successfully" });
    }
  } catch (err: any) {
    console.error("Error processing payment:", err.message);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/getPayments/:username", async (req, res) => {
  const { username } = req.params;

  console.log(username);

  try {
    const { data: userData, error: userError } = await supabase
      .from("users")
      .select("user_id")
      .eq("username", username)
      .single();

    if (userError || !userData) {
      console.error("Error fetching user:", userError?.message);
      return res.status(404).json({ error: "User not found" });
    }

    const userId = userData.user_id;
    console.log("Current user ID:", userId);

    const { data: paymentsData, error: paymentsError } = await supabase
      .from("outstanding_payments")
      .select("payment_name, amount_due, status, amount_paid")
      .eq("user_id", userId);

    if (paymentsError) {
      console.error("Error fetching payments:", paymentsError.message);
      return res.status(500).json({ error: "Error fetching payments" });
    }

    console.log("Payments data:", paymentsData);

    return res.status(200).json(paymentsData);
  } catch (err: any) {
    console.error("Error processing payments:", err.message);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/getUserID/:username", async (req, res) => {
  const { username } = req.params;

  try {
    const { data: userData, error: userError } = await supabase
      .from("users")
      .select("user_id")
      .eq("username", username)
      .single();

    if (userError || !userData) {
      console.error("Error fetching user:", userError?.message);
      return res.status(404).json({ error: "User not found" });
    }

    return res.status(200).json(userData.user_id);
  } catch (err: any) {
    console.error("Error processing request:", err.message);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/transactionHistory/:currentUsername", async (req, res) => {
  const { currentUsername } = req.params;

  try {
    const { data: userData, error: userError } = await supabase
      .from("users")
      .select("user_id")
      .eq("username", currentUsername)
      .single();

    if (userError || !userData) {
      console.error("Error fetching user:", userError?.message);
      return res.status(404).json({ error: "User not found" });
    }

    const { data: transactions, error: transactionError } = await supabase
      .from("transactions")
      .select("*")
      .eq("user_id", userData.user_id);

    if (transactionError) {
      console.error("Error fetching transactions:", transactionError?.message);
      return res
        .status(500)
        .json({ error: "Error fetching transaction history" });
    }

    return res.status(200).json({ data: transactions });
  } catch (err: any) {
    console.error("Error processing request:", err.message);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/authenticated", (req, res) => {
  if (req.isAuthenticated()) {
    console.log("is authenticated");
    res.redirect("http://localhost:5173/Dashboard");
  } else {
    res.redirect("http://localhost:5173/register");
  }
});

app.get("/", (req, res) => {
  res.send("welcome");
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
