import * as React from 'react';
import Avatar from '@mui/material/Avatar';
import Button from '@mui/material/Button';
import CssBaseline from '@mui/material/CssBaseline';
import TextField from '@mui/material/TextField';
import Link from '@mui/material/Link';
import Grid from '@mui/material/Grid';
import Box from '@mui/material/Box';
import LockOutlinedIcon from '@mui/icons-material/LockOutlined';
import Typography from '@mui/material/Typography';
import Container from '@mui/material/Container';
import { createTheme, ThemeProvider } from '@mui/material/styles';
import InputLabel from '@mui/material/InputLabel';
import MenuItem from '@mui/material/MenuItem';
import axios from 'axios';
import FormControl from '@mui/material/FormControl';
import Select from '@mui/material/Select';
import { ButtonBase } from '@mui/material';
import { useNavigate } from 'react-router-dom';

function Copyright(props) {
  return (
    <Typography variant="body2" color="text.secondary" align="center" {...props}>
      {'Copyright © '}
      <Link color="inherit" href="https://mui.com/">
      Online Course Managment System
      </Link>{' '}
      {new Date().getFullYear()}
      {'.'}
    </Typography>
  );
}

const theme = createTheme();

export default function SignUp() {
  const navigate = useNavigate();
  const [error, setError] = React.useState('');
  const [role, setRole] = React.useState('');

  const handleChange = (event) => {
    setRole(event.target.value);
  };

  const handleSubmit = (event) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const signupData = {
      email: data.get('email'),
      password: data.get('password'),
      phone: data.get('phone'),
      role: data.get('role'),
      username: data.get('firstName') + ' ' + data.get('lastName'),
    };
    console.log('Signup Data:', signupData); // Debugging statement
    axios.post('http://localhost:8080/user/signup', signupData)
      .then((resp) => {
        console.log('Response:', resp); // Log the response
        setError('');
        navigate('/');
      })
      .catch((err) => {
        console.log('Error:', err); // Log the error
        if (err.response) {
          console.log('Error Response Data:', err.response.data); // Log error response data
          console.log('Error Response Status:', err.response.status); // Log error response status
          console.log('Error Response Headers:', err.response.headers); // Log error response headers
          setError(err.response.data.error);
        } else if (err.request) {
          console.log('Error Request:', err.request); // Log error request
          setError('No response received from server.');
        } else {
          console.log('Error Message:', err.message); // Log error message
          setError('An error occurred. Please try again later.');
        }
      });
  };

  return (
    <ThemeProvider theme={theme}>
      <Container component="main" maxWidth="xs">
        <CssBaseline />
        <Box
          sx={{
            marginTop: 8,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
          }}
        >
          <Avatar sx={{ m: 1, bgcolor: 'secondary.main' }}>
            <LockOutlinedIcon />
          </Avatar>
          <Typography component="h1" variant="h5">
            Sign up
          </Typography>
          <Box component="form" noValidate onSubmit={handleSubmit} sx={{ mt: 3 }}>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <TextField
                  autoComplete="given-name"
                  name="firstName"
                  required
                  fullWidth
                  id="firstName"
                  label="First Name"
                  autoFocus
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  required
                  fullWidth
                  id="lastName"
                  label="Last Name"
                  name="lastName"
                  autoComplete="family-name"
                />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  required
                  fullWidth
                  id="email"
                  label="Email Address"
                  name="email"
                  autoComplete="email"
                />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  required
                  fullWidth
                  name="password"
                  label="Password"
                  type="password"
                  id="password"
                  autoComplete="new-password"
                />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  required
                  fullWidth
                  name="phone"
                  label="Phone"
                  id="phone"
                />
              </Grid>
              <Grid item xs={12}>
                <FormControl fullWidth required>
                  <InputLabel id="role-label">Role</InputLabel>
                  <Select
                    labelId="role"
                    id="role"
                    name="role"
                    value={role}
                    onChange={handleChange}
                    autoWidth
                    label="Role"
                  >
                    <MenuItem value={'TEACHER'}>Instructor</MenuItem>
                    <MenuItem value={'STUDENT'}>Student</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
            </Grid>
            {error && (
              <Typography component="h3" variant="h5" color="error">
                {error}
              </Typography>
            )}
            <Button
              type="submit"
              fullWidth
              variant="contained"
              sx={{ mt: 3, mb: 2 }}
            >
              Sign Up
            </Button>
            <Grid container justifyContent="flex-end">
              <Grid item>
                <ButtonBase
                  sx={{ mt: 1, mb: 1 }}
                  style={{
                    color: 'blue',
                    cursor: 'pointer',
                  }}
                  onClick={() => navigate("/")}
                >
                  {"Already have an account? Sign in"}
                </ButtonBase>
              </Grid>
            </Grid>
          </Box>
        </Box>
        <Copyright sx={{ mt: 5 }} />
      </Container>
    </ThemeProvider>
  );
}