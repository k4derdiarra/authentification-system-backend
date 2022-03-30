import { Test, TestingModule } from '@nestjs/testing';
import { AppModule } from '../../../app.module';
import { PrismaService } from '../../../prisma/prisma.service';
import { GoogleAuthDto, LocalSignupAuthDto } from '../../dto';
import { AuthService } from '../../auth.service';
import { JwtService } from '@nestjs/jwt';
import { Tokens } from '../../types';

describe('Auth Int', () => {
  let prisma: PrismaService;
  let jwtService: JwtService;
  let authService: AuthService;
  let moduleRef: TestingModule;
  beforeAll(async () => {
    moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    prisma = moduleRef.get<PrismaService>(PrismaService);
    authService = moduleRef.get<AuthService>(AuthService);
    jwtService = moduleRef.get<JwtService>(JwtService);
    await prisma.cleanDatabase();
  });

  afterAll(async () => {
    await moduleRef.close();
  });

  describe('Signup', () => {
    beforeAll(async () => {
      await prisma.cleanDatabase();
    });

    const user: LocalSignupAuthDto = {
      email: 'kader@gmail.com',
      password: 'super-strong-pwd',
      firstName: 'Kader',
      lastName: 'Diarra',
    };

    it('Should signup', async () => {
      const tokens = await authService.signupLocal(user);

      expect(tokens.access_token).toBeTruthy();
      expect(tokens.refresh_token).toBeTruthy();
    });
    it('Should throw error if user already exist', async () => {
      let tokens: Tokens | undefined;
      try {
        tokens = await authService.signupLocal(user);
      } catch (error) {
        expect(error.status).toBe(403);
      }

      expect(tokens).toBe(undefined);
    });
  });

  describe('Sigin', () => {
    beforeAll(async () => {
      await prisma.cleanDatabase();
    });

    it('Should signin', async () => {
      await authService.signupLocal({
        email: 'kader@gmail.com',
        password: 'super-strong-pwd',
        firstName: 'Kader',
        lastName: 'Diarra',
      });

      const tokens = await authService.signinLocal({
        email: 'kader@gmail.com',
        password: 'super-strong-pwd',
      });

      expect(tokens.access_token).toBeTruthy();
      expect(tokens.refresh_token).toBeTruthy();
    });
    it('Should throw error if email wrong', async () => {
      let tokens: Tokens | undefined;

      try {
        tokens = await authService.signinLocal({
          email: 'toto@gmail.com',
          password: 'super-strong-pwd',
        });
      } catch (error) {
        expect(error.status).toBe(403);
      }

      expect(tokens).toBe(undefined);
    });

    it('Should throw error if password wrong', async () => {
      let tokens: Tokens | undefined;

      try {
        tokens = await authService.signinLocal({
          email: 'kader@gmail.com',
          password: 'super-weak-pwd',
        });
      } catch (error) {
        expect(error.status).toBe(403);
      }

      expect(tokens).toBe(undefined);
    });

    it('Should login with google', async () => {
      const dto: GoogleAuthDto = {
        email: 'aziz@gmail.com',
        firstName: 'Aziz',
        lastName: 'Diarra',
        picture: 'google.com',
        provider: 'google',
        accessToken: 'google-access-token',
        refreshToken: 'google-refresh-token',
      };
      const tokens = await authService.signinGoogle(dto);

      expect(tokens.access_token).toBeTruthy();
      expect(tokens.refresh_token).toBeTruthy();
    });
  });

  describe('logout', () => {
    beforeAll(async () => {
      await prisma.cleanDatabase();
    });

    it('should pass if call to non existent user', async () => {
      const result = await authService.logout(456);
      expect(result).toBeDefined();
    });

    it('Should logout', async () => {
      await authService.signupLocal({
        email: 'kader@gmail.com',
        password: 'super-strong-pwd',
        firstName: 'Kader',
        lastName: 'Diarra',
      });

      let user = await prisma.user.findUnique({
        where: { email: 'kader@gmail.com' },
      });

      expect(user?.hashedRefreshToken).toBeTruthy();

      const isLogout = await authService.logout(user.id);
      expect(isLogout).toBe(true);

      user = await prisma.user.findUnique({
        where: { email: 'kader@gmail.com' },
      });
      expect(user?.hashedRefreshToken).toBeFalsy();
    });
  });

  describe('refresh', () => {
    beforeAll(async () => {
      await prisma.cleanDatabase();
    });

    const user: LocalSignupAuthDto = {
      email: 'kader@gmail.com',
      password: 'super-strong-pwd',
      firstName: 'Kader',
      lastName: 'Diarra',
    };

    it('should throw if user logged out', async () => {
      // signup and save refresh token
      const _tokens = await authService.signupLocal(user);

      const rt = _tokens.refresh_token;

      // get user id from refresh token
      // also possible to get using prisma like above
      // but since we have the rt already, why not just decoding it
      const decoded = jwtService.decode(rt);
      const userId = Number(decoded?.sub);

      // logout the user so the hashedRt is set to null
      await authService.logout(userId);

      let tokens: Tokens | undefined;
      try {
        tokens = await authService.refreshTokens(userId, rt);
      } catch (error) {
        expect(error.status).toBe(403);
      }

      expect(tokens).toBeUndefined();
    });

    it('should throw if refresh token incorrect', async () => {
      await prisma.cleanDatabase();

      const _tokens = await authService.signupLocal(user);

      const rt = _tokens.refresh_token;

      const decoded = jwtService.decode(rt);
      const userId = Number(decoded?.sub);

      let tokens: Tokens | undefined;
      try {
        tokens = await authService.refreshTokens(userId, rt + 'a');
      } catch (error) {
        expect(error.status).toBe(403);
      }

      expect(tokens).toBeUndefined();
    });

    it('Should refresh tokens', async () => {
      await prisma.cleanDatabase();
      const _tokens = await authService.signupLocal(user);

      const rt = _tokens.refresh_token;
      const at = _tokens.access_token;

      const decoded = jwtService.decode(rt);
      const userId = Number(decoded?.sub);

      await new Promise((resolve, reject) => {
        setTimeout(() => {
          resolve(true);
        }, 1000);
      });

      const tokens = await authService.refreshTokens(userId, rt);
      expect(tokens).toBeDefined();

      // refreshed tokens should be different
      expect(tokens.access_token).not.toBe(at);
      expect(tokens.refresh_token).not.toBe(rt);
    });
  });
});
