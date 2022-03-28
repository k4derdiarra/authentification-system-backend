import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { GetUser } from '../common/decorators';
import { GoogleAuthDto, LocalSignupAuthDto } from './dto';
import { LocalSigninAuthDto } from './dto';
import { GoogleAuthGuard, JwtRefreshTokenGuard } from './guard';
import { Tokens } from './types';
import { Public } from '../common/decorators';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED)
  signupLocal(@Body() dto: LocalSignupAuthDto): Promise<Tokens> {
    return this.authService.signupLocal(dto);
  }

  @Public()
  @Post('local/signin')
  @HttpCode(HttpStatus.OK)
  signinLocal(@Body() dto: LocalSigninAuthDto): Promise<Tokens> {
    return this.authService.signinLocal(dto);
  }

  @Public()
  @Get('google')
  @UseGuards(GoogleAuthGuard)
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  googleAuth() {}

  @Public()
  @Get('google/redirect')
  @UseGuards(GoogleAuthGuard)
  @HttpCode(HttpStatus.OK)
  googleAuthRedirect(@GetUser() dto: GoogleAuthDto): Promise<Tokens> {
    return this.authService.signinGoogle(dto);
  }

  @Get('logout')
  @HttpCode(HttpStatus.OK)
  logout(@GetUser('id') userId: number): Promise<boolean> {
    return this.authService.logout(userId);
  }

  @Public()
  @UseGuards(JwtRefreshTokenGuard)
  @Get('refresh')
  @HttpCode(HttpStatus.OK)
  refreshTokens(
    @GetUser('sub') userId: number,
    @GetUser('refreshToken') refreshToken: string,
  ): Promise<Tokens> {
    return this.authService.refreshTokens(userId, refreshToken);
  }
}
