import type { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";

export interface AuthRequest extends Request {
  userId?: number;
}

interface TokenPayload {
  userId: number;
}

export function authMiddleware(
  request: AuthRequest,
  response: Response,
  next: NextFunction
) {
  const authorization = request.headers.authorization;

  if (!authorization) {
    return response.status(401).json({
      message: "Token não informado",
    });
  }

  const [type, token] = authorization.split(" ");

  if (type !== "Bearer" || !token) {
    return response.status(401).json({
      message: "Token inválido",
    });
  }

  try {
    const secret = process.env.JWT_SECRET;

    if (!secret) {
      throw new Error("JWT_SECRET não configurado");
    }

    const decoded = jwt.verify(token, secret) as TokenPayload;

    request.userId = decoded.userId;

    return next();
  } catch {
    return response.status(401).json({
      message: "Token inválido ou expirado",
    });
  }
}