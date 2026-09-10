// src/env.ts
import { cleanEnv, str, url } from 'envalid';

export const env = cleanEnv(process.env, {
  DATABASE_URL: str(),
  API_SECRET_KEY: str(),
});