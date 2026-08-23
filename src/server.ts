import "dotenv/config";

import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";

import { prisma } from "./lib/prisma.js";
import {
  createUserSchema,
  forgotPasswordSchema,
  loginSchema,
  resetPasswordSchema,
} from "./schemas/user.schema.js";

import {
  authMiddleware,
  type AuthRequest,
} from "./middlewares/auth.js";

const app = express();

app.use(cors());
app.use(express.json());

app.get("/health", (request, response) => {
  return response.json({
    message: "API funcionando",
  });
});

/*
  CADASTRO
*/
app.post("/users", async (request, response) => {
  const result = createUserSchema.safeParse(request.body);

  if (!result.success) {
    return response.status(400).json({
      message: "Dados inválidos",
      errors: result.error.flatten().fieldErrors,
    });
  }

  const { name, email, password } = result.data;

  const userAlreadyExists = await prisma.user.findUnique({
    where: {
      email,
    },
  });

  if (userAlreadyExists) {
    return response.status(409).json({
      message: "E-mail já cadastrado",
    });
  }

  const passwordHash = await bcrypt.hash(password, 10);

  const user = await prisma.user.create({
    data: {
      name,
      email,
      password: passwordHash,
    },
  });

  return response.status(201).json({
    id: user.id,
    name: user.name,
    email: user.email,
  });
});

/*
  LOGIN
*/
app.post("/login", async (request, response) => {
  const result = loginSchema.safeParse(request.body);

  if (!result.success) {
    return response.status(400).json({
      message: "Dados inválidos",
      errors: result.error.flatten().fieldErrors,
    });
  }

  const { email, password } = result.data;

  const user = await prisma.user.findUnique({
    where: {
      email,
    },
  });

  if (!user) {
    return response.status(401).json({
      message: "E-mail ou senha incorretos",
    });
  }

  const passwordMatches = await bcrypt.compare(
    password,
    user.password
  );

  if (!passwordMatches) {
    return response.status(401).json({
      message: "E-mail ou senha incorretos",
    });
  }

  const secret = process.env.JWT_SECRET;

  if (!secret) {
    return response.status(500).json({
      message: "JWT_SECRET não configurado",
    });
  }

  const token = jwt.sign(
    {
      userId: user.id,
    },
    secret,
    {
      expiresIn: "1d",
    }
  );

  return response.json({
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
    },
    token,
  });
});

/*
  ROTA PRIVADA
*/
app.get(
  "/me",
  authMiddleware,
  async (request: AuthRequest, response) => {
    const user = await prisma.user.findUnique({
      where: {
        id: request.userId,
      },
      select: {
        id: true,
        name: true,
        email: true,
      },
    });

    if (!user) {
      return response.status(404).json({
        message: "Usuário não encontrado",
      });
    }

    return response.json(user);
  }
);

/*
  RECUPERAÇÃO DE SENHA
*/
app.post("/forgot-password", async (request, response) => {
  const result = forgotPasswordSchema.safeParse(request.body);

  if (!result.success) {
    return response.status(400).json({
      message: "E-mail inválido",
    });
  }

  const { email } = result.data;

  const user = await prisma.user.findUnique({
    where: {
      email,
    },
  });

  if (!user) {
    return response.status(404).json({
      message: "Usuário não encontrado",
    });
  }

  const resetCode = "123456";

  console.log(
    `Código de recuperação para ${email}: ${resetCode}`
  );

  return response.json({
    message: "Código de recuperação gerado",
  });
});

/*
  REDEFINIR SENHA
*/
app.post("/reset-password", async (request, response) => {
  const result = resetPasswordSchema.safeParse(request.body);

  if (!result.success) {
    return response.status(400).json({
      message: "Dados inválidos",
      errors: result.error.flatten().fieldErrors,
    });
  }

  const { email, code, newPassword } = result.data;

  if (code !== "123456") {
    return response.status(400).json({
      message: "Código inválido",
    });
  }

  const user = await prisma.user.findUnique({
    where: {
      email,
    },
  });

  if (!user) {
    return response.status(404).json({
      message: "Usuário não encontrado",
    });
  }

  const passwordHash = await bcrypt.hash(newPassword, 10);

  await prisma.user.update({
    where: {
      email,
    },
    data: {
      password: passwordHash,
    },
  });

  return response.json({
    message: "Senha alterada com sucesso",
  });
});

app.listen(3333, () => {
  console.log("Servidor rodando na porta 3333");
});