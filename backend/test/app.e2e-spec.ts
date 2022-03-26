import { Test, TestingModule } from '@nestjs/testing';
import * as pactum from 'pactum';
import { HttpStatus, INestApplication, ValidationPipe } from '@nestjs/common';
import { AppModule } from '../src/app.module';
import { AuthDto } from 'src/auth/dto';
import { PrismaService } from '../src/prisma/prisma.service';

describe('App e2e', () => {
  let app: INestApplication;
  let prisma: PrismaService;

  beforeAll(async () => {
    const moduleRef: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ whitelist: true }));
    await app.init();
    await app.listen(3339);

    prisma = app.get<PrismaService>(PrismaService);
    await prisma.cleanDb();
    pactum.request.setBaseUrl('http://localhost:3339/');
  });

  afterAll(() => {
    app.close();
  });

  describe('Auth', () => {
    const dto: AuthDto = {
      email: 'kader@gmail.com',
      password: 'super-strong-pwd',
    };

    describe('Signup', () => {
      describe('Signup Local', () => {
        it('Should throw error if email empty', () => {
          return pactum
            .spec()
            .post('auth/local/signup')
            .withBody({ password: 'super-strong-pwd' })
            .expectStatus(HttpStatus.BAD_REQUEST);
        });

        it('Should throw error if password empty', () => {
          return pactum
            .spec()
            .post('auth/local/signup')
            .withBody({ email: 'kader@gmail.com' })
            .expectStatus(HttpStatus.BAD_REQUEST);
        });

        it('Should throw error if no body provided', () => {
          return pactum
            .spec()
            .post('auth/local/signup')
            .expectStatus(HttpStatus.BAD_REQUEST);
        });

        it('Should signup', () => {
          return pactum
            .spec()
            .post('auth/local/signup')
            .withBody(dto)
            .expectStatus(HttpStatus.CREATED)
            .expectJsonSchema('access_token', { type: 'string' });
        });
      });

      describe('Signup Google', () => {
        it.todo('Should signin with google');
      });
    });

    describe('Signin', () => {
      describe('Signin Local', () => {
        it('Should throw error if email empty', () => {
          return pactum
            .spec()
            .post('auth/local/signin')
            .withBody({ password: 'super-strong-pwd' })
            .expectStatus(HttpStatus.BAD_REQUEST);
        });

        it('Should throw error if password empty', () => {
          return pactum
            .spec()
            .post('auth/local/signin')
            .withBody({ email: 'kader@gmail.com' })
            .expectStatus(HttpStatus.BAD_REQUEST);
        });

        it('Should throw error if no body provided', () => {
          return pactum
            .spec()
            .post('auth/local/signin')
            .expectStatus(HttpStatus.BAD_REQUEST);
        });

        it('Should signin', () => {
          return pactum
            .spec()
            .post('auth/local/signin')
            .withBody(dto)
            .expectStatus(HttpStatus.CREATED)
            .expectJsonSchema('access_token', { type: 'string' })
            .stores('userAccessToken', 'access_token');
        });
      });
    });

    describe('User', () => {
      describe('Get me', () => {
        it('Should get current user', () => {
          return pactum
            .spec()
            .get('users/me')
            .withHeaders({ Authorization: 'Bearer $S{userAccessToken}' })
            .expectStatus(HttpStatus.OK)
            .inspect();
        });
      });
    });
  });
});
