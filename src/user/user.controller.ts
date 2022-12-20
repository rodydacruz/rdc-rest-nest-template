import { Controller, Get, UseGuards, Req } from '@nestjs/common';
import { User } from '@prisma/client';
import { Request } from 'express';
import { GetUser } from '../auth/decorator';
import { JwtGuard } from '../auth/guard';


@UseGuards(JwtGuard)
@Controller('users')
export class UserController {
    
    @Get('me')
    getMe(@GetUser() user: User) {
        return user;
    }
}
