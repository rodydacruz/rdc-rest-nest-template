import { Injectable } from "@nestjs/common";
import { ForbiddenException } from "@nestjs/common/exceptions";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
const argon = require('argon2');

@Injectable({})
export class AuthService {
    constructor(private prisma: PrismaService) { }
    async signup(dto: AuthDto) {
        //Generate the password
        const hash = await argon.hash(dto.password);
        //save the new user
        try {
            const user = await this.prisma.user.create(
                {
                    data: {
                        email: dto.email,
                        hash
                    }
                },);

            delete user.hash
            // return the saved user
            return user;
        } catch (error) {
            if(error instanceof PrismaClientKnownRequestError) {
                if (error.code === 'P2002') {
                    throw new ForbiddenException('Credentials Taken')
                }
            }
            throw error;
        }

    }

    signin() { 

        //fing the user
        //comparee password


        //sendbacl the user
    }
}