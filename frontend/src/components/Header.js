import { NavLink } from 'react-router-dom';
import './Header.css';


export default function Header() {
  return (
    <header className="header">
      <NavLink to="/" className="header__logo">
        Sentinel
      </NavLink>
    </header>
  );
}
