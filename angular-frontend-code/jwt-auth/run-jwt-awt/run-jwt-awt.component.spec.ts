import { ComponentFixture, TestBed } from '@angular/core/testing';

import { RunJwtAwtComponent } from './run-jwt-awt.component';

describe('RunJwtAwtComponent', () => {
  let component: RunJwtAwtComponent;
  let fixture: ComponentFixture<RunJwtAwtComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [RunJwtAwtComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(RunJwtAwtComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
