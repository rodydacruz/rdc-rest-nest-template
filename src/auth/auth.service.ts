import { Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
const argon = require('argon2');

@Injectable({})
export class AuthService {
    constructor(private prisma: PrismaService) {}
    signup(dto: AuthDto) {
        //Generate the password
        const hash = argon.hash(dto.password);
        //save the new user
        return{
            sms: 'I am singupo',
        }
    }

    signin() {}
}